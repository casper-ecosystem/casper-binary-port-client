use std::{fs::File, io::Read, process::ExitCode};

use crate::error::Error;
use args::Commands;
use clap::Parser;
use information::handle_information_request;
use raw::{handle_raw, OutputOption};
use record::handle_record_request;
use state::handle_state_request;
use transaction::{handle_speculative_execution_request, handle_try_accept_transaction_request};
use utils::print_response;

mod args;
mod error;
mod information;
mod json_print;
mod raw;
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
        Commands::Raw {
            raw_hex,
            file_path,
            output_to_console,
            output_file,
        } => {
            let output_option = unpack_output_option(output_to_console, output_file);
            let bytes_ret = unpack_bytes(raw_hex, file_path);
            match bytes_ret {
                Ok(bytes) => handle_raw(&args.node_address, bytes, output_option).await,
                Err(err) => Err(err),
            }
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

fn unpack_output_option(
    output_to_console: Option<bool>,
    output_file: Option<String>,
) -> OutputOption {
    match (output_to_console, output_file) {
        (None, None) => OutputOption::Muffle,
        (None, Some(file_path)) => OutputOption::ToFile { file_path },
        (Some(true), None) => OutputOption::ToConsole,
        (Some(false), None) => OutputOption::Muffle,
        (Some(_), Some(_)) => panic!("Both output options should never be present"),
    }
}

fn unpack_bytes(raw_hex: Option<String>, file_path: Option<String>) -> Result<Vec<u8>, Error> {
    match (raw_hex, file_path) {
        (None, None) => Err(Error::EitherHexOrFileRequired),
        (None, Some(file_path)) => {
            let mut file = File::open(&file_path).map_err(|err| Error::FromFile {
                file_path: file_path.clone(),
                err,
            })?;
            let mut data = vec![];
            file.read_to_end(&mut data)
                .map_err(|err| Error::FromFile { file_path, err })?;
            Ok(data)
        }
        (Some(hex), None) => hex::decode(hex).map_err(Error::FromHex),
        (Some(_), Some(_)) => Err(Error::EitherHexOrFileRequired),
    }
}
