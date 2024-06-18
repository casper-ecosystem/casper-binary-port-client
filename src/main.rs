use std::process::ExitCode;

use args::Commands;
use clap::Parser;
use information::handle_information_request;
use record::handle_record_request;
use state::handle_state_request;

mod args;
mod error;
mod information;
mod record;
mod state;
mod utils;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = args::Args::parse();

    let result = match args.commands {
        Commands::Information(req) => handle_information_request(&args.node_address, req).await,
        Commands::Record { id, key } => handle_record_request(&args.node_address, id, &key).await,
        Commands::State(req) => handle_state_request(&args.node_address, req).await,
    };

    if let Err(err) = result {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }

    return ExitCode::SUCCESS;
}
