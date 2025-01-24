use clap::{Parser, Subcommand};

use crate::{information::Information, state::State};

#[derive(Debug, Subcommand)]
pub(super) enum Commands {
    /// Send information request of a given kind.
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
    /// Retrieves data from the global state.
    #[clap(subcommand)]
    State(State),
    /// Sends a transaction to the network for inclusion.
    TryAcceptTransaction {
        #[clap(long, short)]
        transaction_file: String,
    },
    /// Sends a transaction to the network for speculative execution.
    TrySpeculativeExecution {
        #[clap(long, short)]
        transaction_file: String,
    },
    /// Sends raw bytes to the network.
    /// You can provide data to this command either with `--file-path` or `--raw-hex` (exactly one of them needs to be provided).
    /// Passing `--file-path <FILE_PATH>` will cause the client to read bytes from <FILE_PATH> and send them to the network as-is (the bytes in the file will be interpreted as a bytesrepr-serialized BinaryRequest struct)
    /// Passing `--raw-hex <HEX_STR>` will cause the client to read HEX_STR and decode it's bytes as if it was a hex string (the bytes in the file will be interpreted as a bytesrepr-serialized BinaryRequest struct)
    ///
    /// This command handles the result in two ways:
    ///
    /// * If the nodes response was erroneous - there will be a "reglar" error message in the console
    ///
    /// * Otherwise, the type of effect will be determined by the passed arguments
    ///
    ///     ** If no arguments were passed, or `--output-to-console false` was passed - the response will be muffled
    ///
    ///     ** If `--output-to-console` is provided - the client will hex-encode bytes of the fetched BinaryResponse and output them in stdout
    ///
    ///     ** If `--output-file <FILE_PATH>` is provided - the client will write bytes of the fetched BinaryResponse in file under `<FILE_PATH>`
    ///
    /// Examples:
    /// ```
    ///  casper-binary-port-client --node-address <node_path> raw --raw-hex 0000020000000000000000000000030000 --output-to-console
    /// ```
    ///  The above will decode bytes from `--raw-hex` interpreting it as a hex-encoded string, send the decoded bytes as-is to the network, interpret the response and, if the response is successfull, output the bytes to console encoded as hex string
    ///
    ///
    /// ```
    ///  casper-binary-port-client --node-address <node_path> raw --file-path /some/path/req.bin --output-file /other/path/res.bin
    /// ```
    ///  The above will read bytes from `--file-path` file, send them as-is to the network, interpret the response and, if the response is successfull, write the whole `BinaryResponse` as bytes to --output-file
    ///
    /// ```
    ///  casper-binary-port-client --node-address <node_path> raw --raw-hex 0000020000000000000000000000030000
    /// ```
    ///  The above will decode bytes from `--raw-hex` interpreting it as a hex-encoded string, send the decoded bytes as-is to the network, interpret the response and, if the response is successfull, muffle the output and produce nothing
    Raw {
        /// string with hex-encoded bytes
        #[clap(long, short, group = "raw-data")]
        raw_hex: Option<String>,
        /// string with path to file containing raw bytes
        #[clap(long, short = 'f', group = "raw-data")]
        file_path: Option<String>,
        #[clap(long, conflicts_with = "output_file")]
        output_to_console: Option<bool>,
        #[clap(long, conflicts_with = "output_to_console")]
        output_file: Option<String>,
    },
}

/// A CLI binary for interacting with the Casper network via the binary protocol.
#[derive(Parser, Debug)]
pub(super) struct Args {
    #[clap(subcommand)]
    pub(super) commands: Commands,
    /// Provides a verbose output as the command is being handled (not supported yet).
    #[clap(long, short, default_value = "false")]
    pub(super) verbose: bool,
    #[clap(long, short, required = true)]
    pub(super) node_address: String,
}
