use diesel::pg::PgConnection;
use diesel::r2d2::{
    self, event as e, Builder, ConnectionManager, HandleEvent, Pool, PooledConnection,
};
use diesel::{sql_query, RunQueryDsl};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, instrument};

use crate::util::futures::{CancelGuard, CancelHandle, CancelToken as _, CancelableError};
use crate::util::store::StoreError;
use crate::util::timed_rw_lock::TimedMutex;

/// A pool goes through several states, and this enum tracks what state we
/// are in, together with the `state_tracker` field on `ConnectionPool`.
/// When first created, the pool is in state `Created`; once we successfully
/// called `setup` on it, it moves to state `Ready`. During use, we use the
/// r2d2 callbacks to determine if the database is available or not, and set
/// the `available` field accordingly. Tracking that allows us to fail fast
/// and avoids having to wait for a connection timeout every time we need a
/// database connection. That avoids overall undesirable states like buildup
/// of queries; instead of queueing them until the database is available,
/// they return almost immediately with an error
enum PoolState {
    /// A connection pool, and all the servers for which we need to
    /// establish fdw mappings when we call `setup` on the pool
    Created(Arc<PoolInner>),
    /// The pool has been successfully set up
    Ready(Arc<PoolInner>),
}

#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<TimedMutex<PoolState>>,
    state_tracker: PoolStateTracker,
    try_always: bool,
}

impl fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("shard", &self)
            .finish()
    }
}

#[derive(Clone)]
struct PoolStateTracker {
    available: Arc<AtomicBool>,
}

impl PoolStateTracker {
    fn new() -> Self {
        Self {
            available: Arc::new(AtomicBool::new(true)),
        }
    }

    fn mark_available(&self) {
        self.available.store(true, Ordering::Relaxed);
    }

    fn mark_unavailable(&self) {
        self.available.store(false, Ordering::Relaxed);
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }
}

impl ConnectionPool {
    #[instrument(skip(postgres_url))]
    pub fn create(
        shard_name: &str,
        postgres_url: String,
        pool_size: u32,
        fdw_pool_size: Option<u32>,
        extra_query_permits: usize,
        connection_timeout: Duration,
        min_idle: Option<u32>,
        idle_timeout: Option<Duration>,
    ) -> ConnectionPool {
        let state_tracker = PoolStateTracker::new();
        let pool = PoolInner::create(
            postgres_url,
            pool_size,
            fdw_pool_size,
            state_tracker.clone(),
            extra_query_permits,
            connection_timeout,
            min_idle,
            idle_timeout,
        );
        let pool_state = PoolState::Created(Arc::new(pool));
        let log_threshold = Duration::from_millis(100);
        ConnectionPool {
            inner: Arc::new(TimedMutex::new(
                pool_state,
                format!("pool-{}", shard_name),
                log_threshold,
            )),
            state_tracker,
            try_always: false,
        }
    }

    /// Return a pool that is ready, i.e., connected to the database. If the
    /// pool has not been set up yet, call `setup`. If there are any errors
    /// or the pool is marked as unavailable, return
    /// `StoreError::DatabaseUnavailable`
    fn get_ready(&self) -> Result<Arc<PoolInner>, StoreError> {
        let mut guard = self.inner.lock();
        if !self.state_tracker.is_available() && !self.try_always {
            // We know that trying to use this pool is point since the
            // database is not available, and will only lead to other
            // operations having to wait until the connection timeout is
            // reached. `TRY_ALWAYS` allows users to force us to try
            // regardless.
            return Err(StoreError::DatabaseUnavailable);
        }

        match &*guard {
            PoolState::Created(pool) => {
                let pool2 = pool.clone();
                *guard = PoolState::Ready(pool.clone());
                self.state_tracker.mark_available();
                Ok(pool2)
            }
            PoolState::Ready(pool) => Ok(pool.clone()),
        }
    }

    pub async fn with_conn<T: Send + 'static>(
        &self,
        f: impl 'static
            + Send
            + FnOnce(
                &PooledConnection<ConnectionManager<PgConnection>>,
                &CancelHandle,
            ) -> Result<T, CancelableError<StoreError>>,
    ) -> Result<T, StoreError> {
        let pool = self.get_ready()?;
        pool.with_conn(f).await
    }

    pub fn get(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, StoreError> {
        self.get_ready()?.get()
    }

    /// Get a connection from the pool for foreign data wrapper access;
    /// since that pool can be very contended, periodically log that we are
    /// still waiting for a connection
    ///
    /// The `timeout` is called every time we time out waiting for a
    /// connection. If `timeout` returns `true`, `get_fdw` returns with that
    /// error, otherwise we try again to get a connection.
    pub fn get_fdw<F>(
        &self,
        timeout: F,
    ) -> Result<PooledConnection<ConnectionManager<PgConnection>>, StoreError>
    where
        F: FnMut() -> bool,
    {
        self.get_ready()?.get_fdw(timeout)
    }

    /// Setup the database for this pool. This includes configuring foreign
    /// data wrappers for cross-shard communication, and running any pending
    /// schema migrations for this database.
    ///
    /// # Panics
    ///
    /// If any errors happen during the migration, the process panics
    pub async fn setup(&self) {
        let pool = self.clone();
        tokio::task::spawn_blocking(move || {
            pool.get_ready().ok();
        })
        .await
        .unwrap();
    }
}

fn brief_error_msg(error: &dyn std::error::Error) -> String {
    // For 'Connection refused' errors, Postgres includes the IP and
    // port number in the error message. We want to suppress that and
    // only use the first line from the error message. For more detailed
    // analysis, 'Connection refused' manifests as a
    // `ConnectionError(BadConnection("could not connect to server:
    // Connection refused.."))`
    error
        .to_string()
        .split("\n")
        .next()
        .unwrap_or("no error details provided")
        .to_string()
}

#[derive(Clone)]
struct ErrorHandler {
    state_tracker: PoolStateTracker,
}

impl ErrorHandler {
    fn new(state_tracker: PoolStateTracker) -> Self {
        Self { state_tracker }
    }
}
impl std::fmt::Debug for ErrorHandler {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Result::Ok(())
    }
}

impl r2d2::HandleError<r2d2::Error> for ErrorHandler {
    fn handle_error(&self, error: r2d2::Error) {
        let msg = brief_error_msg(&error);

        // Don't count canceling statements for timeouts etc. as a
        // connection error. Unfortunately, we only have the textual error
        // and need to infer whether the error indicates that the database
        // is down or if something else happened. When querying a replica,
        // these messages indicate that a query was canceled because it
        // conflicted with replication, but does not indicate that there is
        // a problem with the database itself.
        //
        // This check will break if users run Postgres (or even graph-node)
        // in a locale other than English. In that case, their database will
        // be marked as unavailable even though it is perfectly fine.
        if msg.contains("canceling statement")
            || msg.contains("no connection to the server")
            || msg.contains("terminating connection due to conflict with recovery")
        {
            return;
        }

        if self.state_tracker.is_available() {
            error!("Postgres connection error: {} ", msg);
        }
        self.state_tracker.mark_unavailable();
    }
}

#[derive(Clone)]
struct EventHandler {
    state_tracker: PoolStateTracker,
}

impl EventHandler {
    fn new(state_tracker: PoolStateTracker) -> Self {
        EventHandler { state_tracker }
    }
}

impl std::fmt::Debug for EventHandler {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Result::Ok(())
    }
}

impl HandleEvent for EventHandler {
    fn handle_acquire(&self, _: e::AcquireEvent) {
        self.state_tracker.mark_available();
    }

    fn handle_checkout(&self, _event: e::CheckoutEvent) {
        self.state_tracker.mark_available();
    }

    fn handle_timeout(&self, event: e::TimeoutEvent) {
        if self.state_tracker.is_available() {
            error!(
                "Connection checkout timed out wait_ms {}",
                event.timeout().as_millis()
            )
        }
        self.state_tracker.mark_unavailable();
    }
}

#[derive(Clone)]
pub struct PoolInner {
    pool: Pool<ConnectionManager<PgConnection>>,
    // A separate pool for connections that will use foreign data wrappers.
    // Once such a connection accesses a foreign table, Postgres keeps a
    // connection to the foreign server until the connection is closed.
    // Normal pooled connections live quite long (up to 10 minutes) and can
    // therefore keep a lot of connections into foreign databases open. We
    // mitigate this by using a separate small pool with a much shorter
    // connection lifetime. Starting with postgres_fdw 1.1 in Postgres 14,
    // this will no longer be needed since it will then be possible to
    // explicitly close connections to foreign servers when a connection is
    // returned to the pool.
    fdw_pool: Option<Pool<ConnectionManager<PgConnection>>>,
    pub limiter: Arc<Semaphore>,
    pub postgres_url: String,

    // Limits the number of graphql queries that may execute concurrently. Since one graphql query
    // may require multiple DB queries, it is useful to organize the queue at the graphql level so
    // that waiting queries consume few resources. Still this is placed here because the semaphore
    // is sized according to the DB connection pool size.
    pub query_semaphore: Arc<tokio::sync::Semaphore>,
}

impl PoolInner {
    fn create(
        postgres_url: String,
        pool_size: u32,
        fdw_pool_size: Option<u32>,
        state_tracker: PoolStateTracker,
        extra_query_permits: usize,
        connection_timeout: Duration,
        min_idle: Option<u32>,
        idle_timeout: Option<Duration>,
    ) -> PoolInner {
        let error_handler = Box::new(ErrorHandler::new(state_tracker.clone()));
        let event_handler = Box::new(EventHandler::new(state_tracker));

        // Connect to Postgres
        let conn_manager = ConnectionManager::new(postgres_url.clone());
        let builder: Builder<ConnectionManager<PgConnection>> = Pool::builder()
            .error_handler(error_handler.clone())
            .event_handler(event_handler.clone())
            .connection_timeout(connection_timeout)
            .max_size(pool_size)
            .min_idle(min_idle)
            .idle_timeout(idle_timeout);
        let pool = builder.build_unchecked(conn_manager);
        let fdw_pool = fdw_pool_size.map(|pool_size| {
            let conn_manager = ConnectionManager::new(postgres_url.clone());
            let builder: Builder<ConnectionManager<PgConnection>> = Pool::builder()
                .error_handler(error_handler)
                .event_handler(event_handler)
                .connection_timeout(connection_timeout)
                .max_size(pool_size)
                .min_idle(min_idle)
                .idle_timeout(idle_timeout);
            builder.build_unchecked(conn_manager)
        });

        let limiter = Arc::new(Semaphore::new(pool_size as usize));
        info!("Pool successfully connected to Postgres");

        let max_concurrent_queries = pool_size as usize + extra_query_permits;
        let query_semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_queries));
        PoolInner {
            postgres_url: postgres_url.clone(),
            pool,
            fdw_pool,
            limiter,
            query_semaphore,
        }
    }

    pub async fn with_conn<T: Send + 'static>(
        &self,
        f: impl 'static
            + Send
            + FnOnce(
                &PooledConnection<ConnectionManager<PgConnection>>,
                &CancelHandle,
            ) -> Result<T, CancelableError<StoreError>>,
    ) -> Result<T, StoreError> {
        let _permit = self.limiter.acquire().await;
        let pool = self.clone();

        let cancel_guard = CancelGuard::new();
        let cancel_handle = cancel_guard.handle();

        let result = tokio::task::spawn_blocking(move || {
            // It is possible time has passed between scheduling on the
            // thread pool and being executed. Time to check for cancel.
            cancel_handle.check_cancel()?;

            // A failure to establish a connection is propagated as though the
            // closure failed.
            let conn = pool
                .get()
                .map_err(|_| CancelableError::Error(StoreError::DatabaseUnavailable))?;

            // It is possible time has passed while establishing a connection.
            // Time to check for cancel.
            cancel_handle.check_cancel()?;

            f(&conn, &cancel_handle)
        })
        .await
        .unwrap(); // Propagate panics, though there shouldn't be any.

        drop(cancel_guard);

        // Finding cancel isn't technically unreachable, since there is nothing
        // stopping the supplied closure from returning Canceled even if the
        // supplied handle wasn't canceled. That would be very unexpected, the
        // doc comment for this function says we will panic in this scenario.
        match result {
            Ok(t) => Ok(t),
            Err(CancelableError::Error(e)) => Err(e),
            Err(CancelableError::Cancel) => panic!("The closure supplied to with_entity_conn must not return Err(Canceled) unless the supplied token was canceled."),
        }
    }

    pub fn get(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, StoreError> {
        self.pool.get().map_err(|_| StoreError::DatabaseUnavailable)
    }

    /// Get a connection from the pool for foreign data wrapper access;
    /// since that pool can be very contended, periodically log that we are
    /// still waiting for a connection
    ///
    /// The `timeout` is called every time we time out waiting for a
    /// connection. If `timeout` returns `true`, `get_fdw` returns with that
    /// error, otherwise we try again to get a connection.
    pub fn get_fdw<F>(
        &self,
        mut timeout: F,
    ) -> Result<PooledConnection<ConnectionManager<PgConnection>>, StoreError>
    where
        F: FnMut() -> bool,
    {
        let pool = match &self.fdw_pool {
            Some(pool) => pool,
            None => {
                let message =
                    "internal error: trying to get fdw connection on a pool that doesn't have any";
                error!("{}", message.to_string());
                return Err(StoreError::ConstraintViolation(message.to_string()));
            }
        };
        loop {
            match pool.get() {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    if timeout() {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    /// Check that we can connect to the database
    pub fn check(&self) -> bool {
        self.pool
            .get()
            .ok()
            .map(|conn| sql_query("select 1").execute(&conn).is_ok())
            .unwrap_or(false)
    }
}
