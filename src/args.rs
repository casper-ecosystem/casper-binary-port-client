use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub(crate) enum Information {
    /// Retrieve block header by height or hash.
    BlockHeader {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Read node uptime.
    Uptime,
    /// Read node status.
    NodeStatus,
    /// Retrieve raw chainspec bytes.
    ChainspecRawBytes,
}

#[derive(Debug, Subcommand)]
pub(super) enum Commands {
    /// Send information request with a given ID and key.
    #[clap(subcommand)]
    Information(Information),
    /// Send record request with a given ID and key.
    #[command(
        after_help = "Please refer to `enum RecordId` from the casper-node repository for valid record IDs."
    )]
    Record {
        #[clap(long, short)]
        id: u16,
        /// Hex-encoded key.
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
