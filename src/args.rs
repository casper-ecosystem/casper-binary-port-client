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
    /// Retrieve block with signatures by height or hash.
    SignedBlock {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Retrieve a transaction with approvals and execution info for a given hash.
    Transaction {
        /// Hash of the transaction to retrieve.
        #[clap(long)]
        hash: String,
        /// Whether to return the deploy with the finalized approvals substituted.
        #[clap(long, short)]
        with_finalized_approvals: bool,
        /// Whether to return the legacy deploy or the new transaction.
        #[clap(long, short)]
        legacy: bool,
    },
    /// Returns connected peers.
    Peers,
    /// Read node uptime.
    Uptime,
    /// Returns last progress of the sync process.
    LastProgress,
    /// Returns current state of the main reactor.
    ReactorState,
    /// Returns network name.
    NetworkName,
    /// Returns consensus validator changes.
    ConsensusValidatorChanges,
    /// Returns status of the BlockSynchronizer.
    BlockSynchronizerStatus,
    /// Available block range request.
    AvailableBlockRange,
    /// Next upgrade request.
    NextUpgrade,
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
