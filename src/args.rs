use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub(crate) enum Information {
    /// Block header request.
    BlockHeader {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Uptime.
    Uptime,
    /// NodeStatus request.
    NodeStatus,
    /// Chainspec raw bytes request.
    ChainspecRawBytes,
}

#[derive(Debug, Subcommand)]
pub(super) enum Commands {
    /// Send information request with a given ID and key.
    #[clap(subcommand)]
    Information(Information),
    /// Send record request with a given ID and key.
    Record {
        #[clap(long, short)]
        id: u16,
        #[clap(long, short)]
        key: String,
    },
}

/// A request to the binary access interface.
#[derive(Parser, Debug)]
pub(super) struct Args {
    #[clap(subcommand)]
    pub(super) commands: Commands,
    // Currently unused.
    #[clap(long, short, default_value = "false")]
    verbose: bool,
}
