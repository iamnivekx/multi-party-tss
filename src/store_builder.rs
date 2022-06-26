use crate::config::{Config, Shard};
use crate::connection_pool::ConnectionPool;
use anyhow::Result;
use tracing::debug;
pub struct StoreBuilder {
    pub enable: bool,
    pub config: Config,
    pub pool: Option<ConnectionPool>,
}

impl StoreBuilder {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
            enable: config.gg20_enable_distributed,
            pool: None,
        }
    }

    pub async fn try_connected(&mut self) -> Result<()> {
        if !self.enable {
            debug!("Disable connection pool");
            Ok(())
        } else {
            let pool = Self::make_pg_pool(&self.config.clone());
            pool.setup().await;
            self.pool = Some(pool);
            Ok(())
        }
    }

    pub fn make_pg_pool(config: &Config) -> ConnectionPool {
        let name = "primary";
        let shard = config.shard.clone();
        let conn_pool = Self::main_pool(name, &shard);
        conn_pool
    }

    /// Create a connection pool for the main database of the primary shard
    /// without connecting to all the other configured databases
    pub fn main_pool(name: &str, shard: &Shard) -> ConnectionPool {
        let pool_size = shard.pool_size.clone();
        let fdw_pool_size = shard.fdw_pool_size.clone();
        let connection_timeout = shard.connection_timeout.clone();
        let extra_query_permits = 0;
        info!(
            "Connecting to Postgres, pool_size {} fdw_pool_size {}",
            pool_size.clone(),
            fdw_pool_size.clone(),
        );
        ConnectionPool::create(
            name,
            shard.connection.to_owned(),
            pool_size.clone(),
            Some(fdw_pool_size),
            extra_query_permits.clone(),
            connection_timeout,
            None,
            None,
        )
    }

    pub fn primary_pool(&self) -> ConnectionPool {
        return self.pool.as_ref().unwrap().clone();
    }
}
