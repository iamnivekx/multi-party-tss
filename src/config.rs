use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use surf::Url;
use tracing::debug;
pub struct Opt {
    // log opt
    pub log_level: String,
    pub log_directory: String,
    pub log_file_prefix_name: String,
    // gg18
    pub gg18_enable_distributed: bool,
    pub gg18_communicate_endpoint: Option<String>,
    // gg20
    pub gg20_enable_distributed: bool,
    pub gg20_communicate_endpoint: Option<String>,
    pub node_request_delay: u64,
    pub node_request_max_timeout: u64,
    // postgres storage
    pub postgres_url: Option<String>,
    pub pg_connection_pool_size: u32,
    pub pg_connection_fdw_pool_size: u32,
    pub pg_connection_extra_query_permits: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub file_log_opt: FileLogOpt,
    pub gg18_opt: GGFutureOpt,
    pub gg20_opt: GGFutureOpt,
    pub shard: Shard,
}

impl Config {
    /// Check that the config is valid.
    fn validate(&mut self) -> Result<()> {
        self.gg18_opt.validate()?;
        self.gg20_opt.validate()?;
        Ok(())
    }

    pub fn load(opt: &Opt) -> Result<Config> {
        debug!("Generating configuration from command line arguments");
        Self::from_opt(opt)
    }

    fn from_opt(opt: &Opt) -> Result<Config> {
        let shard = Shard::from_opt(opt)?;
        let file_log_opt = FileLogOpt::from_opt(opt)?;
        let gg18_opt = GGFutureOpt::new(
            opt.gg18_enable_distributed,
            opt.gg18_communicate_endpoint.clone(),
            None,
            None,
        );
        let gg20_opt = GGFutureOpt::new(
            opt.gg20_enable_distributed.clone(),
            opt.gg20_communicate_endpoint.clone(),
            Some(opt.node_request_delay),
            Some(opt.node_request_max_timeout),
        );
        let mut config = Config {
            gg18_opt,
            gg20_opt,
            file_log_opt,
            shard,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self)?)
    }

    pub fn enable_store(&self) -> bool {
        self.gg20_opt.enable_distributed.clone()
    }

    pub fn gg18_communicate_endpoint(&self) -> Result<String> {
        if !self.gg18_opt.enable_distributed {
            return Err(anyhow!("GG18 unimplemented"));
        }
        let endpoint = self
            .gg18_opt
            .communicate_endpoint
            .clone()
            .context("GG18 endpoint uninitialized")?;
        Ok(endpoint)
    }

    pub fn gg20_communicate_endpoint(&self) -> Result<String> {
        if !self.gg20_opt.enable_distributed {
            return Err(anyhow!("GG20 unimplemented"));
        }
        let endpoint = self
            .gg20_opt
            .communicate_endpoint
            .clone()
            .context("GG20 endpoint uninitialized")?;
        Ok(endpoint)
    }

    pub fn node_request_max_timeout(&self) -> u64 {
        self.gg20_opt.node_request_max_timeout.clone()
    }

    pub fn node_request_delay(&self) -> u64 {
        self.gg20_opt.node_request_delay.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Shard {
    pub connection: String,
    pub weight: usize,
    pub pool_size: u32,
    pub fdw_pool_size: u32,
    pub extra_query_permits: u32,
    pub connection_timeout: Duration,
}

impl Shard {
    fn from_opt(opt: &Opt) -> Result<Self> {
        let postgres_url = opt
            .postgres_url
            .as_ref()
            .expect("validation checked that postgres_url is set");
        let pool_size = opt.pg_connection_pool_size.clone();
        let fdw_pool_size = opt.pg_connection_fdw_pool_size.clone();
        let extra_query_permits = opt.pg_connection_extra_query_permits.clone();
        let connection_timeout = Duration::from_secs(60);

        Ok(Self {
            connection: postgres_url.clone(),
            weight: 1,
            pool_size,
            fdw_pool_size,
            connection_timeout,
            extra_query_permits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileLogOpt {
    pub level: String,
    pub directory: String,
    pub file_prefix_name: String,
}

impl FileLogOpt {
    fn from_opt(opt: &Opt) -> Result<Self> {
        let path =
            env::current_dir().map_err(|e| anyhow!("failed to get current dir path {:?}", e))?;
        let log_directory = path.join(opt.log_directory.clone());
        Ok(Self {
            level: opt.log_level.clone(),
            directory: log_directory
                .to_str()
                .expect("log_directory is not a valid path")
                .to_string(),
            file_prefix_name: opt.log_file_prefix_name.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GGFutureOpt {
    pub enable_distributed: bool,
    pub communicate_endpoint: Option<String>,
    pub node_request_delay: u64,
    pub node_request_max_timeout: u64,
}

impl GGFutureOpt {
    pub fn validate(&self) -> Result<()> {
        if self.enable_distributed {
            if let Some(endpoint) = self.communicate_endpoint.clone() {
                let _url = Url::parse(endpoint.clone().as_str()).map_err(|e| {
                    anyhow!(
                        "the communicate_endpoint url {} is not a legal URL: {}",
                        endpoint,
                        e
                    )
                })?;
            } else {
                return Err(anyhow!("the communicate_endpoint url do not set"));
            }
        }
        Ok(())
    }
    pub fn new(
        enable_distributed: bool,
        communicate_endpoint: Option<String>,
        node_request_delay: Option<u64>,
        node_request_max_timeout: Option<u64>,
    ) -> Self {
        let node_request_delay = node_request_delay.unwrap_or(0);
        let node_request_max_timeout = node_request_max_timeout.unwrap_or(0);
        Self {
            enable_distributed,
            communicate_endpoint,
            node_request_delay,
            node_request_max_timeout,
        }
    }
}
