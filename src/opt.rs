use structopt::StructOpt;

use crate::config;

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "multi_party_server", about = "An Opt of StructOpt usage.")]
pub struct Opt {
    #[structopt(
        long,
        value_name = "enable the gg18 distributed",
        env = "GG18_ENABLE_DISTRIBUTED",
        help = "enable the gg18 distributed futures"
    )]
    pub gg18_enable_distributed: bool,
    #[structopt(
        long,
        value_name = "gg18 communicate endpoint",
        env = "GG18_COMMUNICATE_ENDPOINT",
        required_if("gg18_enable_distributed", "true"),
        help = "gg18 communicate endpoint"
    )]
    pub gg18_communicate_endpoint: Option<String>,

    #[structopt(
        long,
        value_name = "enable the gg18 distributed",
        env = "GG20_ENABLE_DISTRIBUTED",
        help = "enable the gg20 distributed futures"
    )]
    pub gg20_enable_distributed: bool,
    #[structopt(
        long,
        value_name = "gg20 communicate endpoint",
        env = "GG20_COMMUNICATE_ENDPOINT",
        required_if("gg20_enable_distributed", "true"),
        help = "used to connect to the g20 communicate server"
    )]
    pub gg20_communicate_endpoint: Option<String>,
    #[structopt(
        long,
        value_name = "node request delay",
        default_value = "100",
        env = "NODE_REQUEST_DELAY",
        help = "node request delay"
    )]
    pub node_request_delay: u64,
    #[structopt(
        long,
        value_name = "node request max_timeout",
        default_value = "60000",
        env = "NODE_REQUEST_MAX_TIMEOUT",
        help = "communicate max timeout"
    )]
    pub node_request_max_timeout: u64,
    #[structopt(
        long,
        value_name = "URL",
        env = "POSTGRES_URL",
        required_if("gg20_enable_distributed", "true"),
        help = "Postgres database URL"
    )]
    pub postgres_url: Option<String>,
    #[structopt(
        long,
        value_name = "URL",
        env = "PG_CONNECTION_POOL_SIZE",
        default_value = "10",
        required_if("gg20_enable_distributed", "true"),
        help = "Postgres connection pool size"
    )]
    pub pg_connection_pool_size: u32,
    #[structopt(
        long,
        value_name = "PG CONNECTION FDW POOL SIZE",
        default_value = "10",
        env = "PG_CONNECTION_FDW_POOL_SIZE",
        required_if("gg20_enable_distributed", "true"),
        help = "Postgres connection fdw pool size"
    )]
    pub pg_connection_fdw_pool_size: u32,
    #[structopt(
        long,
        value_name = "PG CONNECTION EXTRA_QUERY PERMITS",
        default_value = "0",
        env = "PG_CONNECTION_EXTRA_QUERY_PERMITS",
        help = "Postgres connection extra query permits"
    )]
    pub pg_connection_extra_query_permits: u32,
}

impl From<Opt> for config::Opt {
    fn from(opt: Opt) -> Self {
        let Opt {
            gg18_enable_distributed,
            gg18_communicate_endpoint,
            gg20_enable_distributed,
            gg20_communicate_endpoint,
            node_request_delay,
            node_request_max_timeout,

            postgres_url,
            pg_connection_pool_size,
            pg_connection_fdw_pool_size,
            pg_connection_extra_query_permits,
            ..
        } = opt;

        config::Opt {
            gg18_enable_distributed,
            gg18_communicate_endpoint,
            gg20_enable_distributed,
            gg20_communicate_endpoint,
            node_request_delay,
            node_request_max_timeout,
            postgres_url,
            pg_connection_pool_size,
            pg_connection_fdw_pool_size,
            pg_connection_extra_query_permits,
        }
    }
}
