use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use surf::Url;
use tracing::debug;
pub struct Opt {
    pub gg18_enable_distributed: bool,
    pub gg18_communicate_endpoint: Option<String>,
    pub gg20_enable_distributed: bool,
    pub gg20_communicate_endpoint: Option<String>,
    pub node_request_delay: u64,
    pub node_request_max_timeout: u64,
    pub postgres_url: Option<String>,
    pub pg_connection_pool_size: u32,
    pub pg_connection_fdw_pool_size: u32,
    pub pg_connection_extra_query_permits: u32,
}

impl Default for Opt {
    fn default() -> Self {
        Opt {
            gg18_enable_distributed: false,
            gg18_communicate_endpoint: None,
            gg20_enable_distributed: false,
            gg20_communicate_endpoint: None,
            node_request_delay: 10,
            node_request_max_timeout: 60 * 1000,
            postgres_url: None,
            pg_connection_pool_size: 10,
            pg_connection_fdw_pool_size: 10,
            pg_connection_extra_query_permits: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub gg18_enable_distributed: bool,
    pub gg18_communicate_endpoint: Option<String>,
    pub gg20_enable_distributed: bool,
    pub gg20_communicate_endpoint: Option<String>,
    pub node_request_delay: Duration,
    pub node_request_max_timeout: Duration,
    pub postgres_url: Option<String>,
    pub shard: Shard,
}

impl Config {
    /// Check that the config is valid.
    fn validate(&mut self) -> Result<()> {
        if self.gg18_enable_distributed {
            if let Some(endpoint) = self.gg18_communicate_endpoint.clone() {
                let _url = Url::parse(endpoint.clone().as_str()).map_err(|e| {
                    anyhow!(
                        "the gg18_communicate_endpoint url {} is not a legal URL: {}",
                        endpoint,
                        e
                    )
                })?;
            } else {
                return Err(anyhow!("the gg18_communicate_endpoint url do not set"));
            }
        }
        if self.gg20_enable_distributed {
            if let Some(endpoint) = self.gg20_communicate_endpoint.clone() {
                let _url = Url::parse(endpoint.clone().as_str()).map_err(|e| {
                    anyhow!(
                        "the gg20_communicate_endpoint url {} is not a legal URL: {}",
                        endpoint,
                        e
                    )
                })?;
            } else {
                return Err(anyhow!("the gg20_communicate_endpoint url do not set"));
            }
        }
        Ok(())
    }

    pub fn load(opt: &Opt) -> Result<Config> {
        debug!("Generating configuration from command line arguments");
        Self::from_opt(opt)
    }

    fn from_opt(opt: &Opt) -> Result<Config> {
        let shard = Shard::from_opt(opt)?;
        let mut config = Config {
            gg18_enable_distributed: opt.gg18_enable_distributed.clone(),
            gg18_communicate_endpoint: opt.gg18_communicate_endpoint.clone(),

            gg20_enable_distributed: opt.gg20_enable_distributed.clone(),
            gg20_communicate_endpoint: opt.gg20_communicate_endpoint.clone(),

            node_request_delay: Duration::from_millis(opt.node_request_delay.clone()),
            node_request_max_timeout: Duration::from_millis(opt.node_request_max_timeout.clone()),
            postgres_url: opt.postgres_url.clone(),
            shard,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self)?)
    }

    pub fn valid_gg18_communicate_endpoint(&self) -> Result<String> {
        if !self.gg18_enable_distributed {
            return Err(anyhow!("GG18 unimplemented"));
        }
        let endpoint = self
            .gg18_communicate_endpoint
            .clone()
            .context("GG18 endpoint uninitialized")?;
        Ok(endpoint)
    }

    pub fn valid_gg20_communicate_endpoint(&self) -> Result<String> {
        if !self.gg20_enable_distributed {
            return Err(anyhow!("GG20 unimplemented"));
        }
        let endpoint = self
            .gg20_communicate_endpoint
            .clone()
            .context("GG20 endpoint uninitialized")?;
        Ok(endpoint)
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
