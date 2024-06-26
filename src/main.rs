use std::process::ExitCode;

use args::Commands;
use clap::Parser;
use information::handle_information_request;
use record::handle_record_request;
use state::handle_state_request;
use transaction::{handle_speculative_execution_request, handle_try_accept_transaction_request};
use utils::print_response;

mod args;
mod error;
mod information;
mod json_print;
mod record;
mod state;
mod transaction;
mod utils;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = args::Args::parse();

    let result = match args.commands {
        Commands::Information(req) => handle_information_request(&args.node_address, req).await,
        Commands::Record { id, key } => handle_record_request(&args.node_address, id, &key).await,
        Commands::State(req) => handle_state_request(&args.node_address, req).await,
        Commands::TryAcceptTransaction { transaction_file } => {
            handle_try_accept_transaction_request(&args.node_address, &transaction_file).await
        }
        Commands::TrySpeculativeExecution { transaction_file } => {
            handle_speculative_execution_request(&args.node_address, &transaction_file).await
        }
    };

    match result {
        Ok(response) => {
            print_response(response);
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    }
}
