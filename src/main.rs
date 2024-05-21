use std::process::ExitCode;

use args::Commands;
use clap::Parser;
use information::handle_information_request;
use record::handle_record_request;

mod args;
mod communication;
mod error;
mod information;
mod record;
mod utils;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = args::Args::parse();

    let result = match args.commands {
        Commands::Information(req) => handle_information_request(req).await,
        Commands::Record { id, key } => handle_record_request(id, &key).await,
    };

    if let Err(err) = result {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }

    return ExitCode::SUCCESS;
}
