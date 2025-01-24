use std::{fs::File, io::Write};

use casper_binary_port_access::send_raw_bytes;
use casper_types::bytesrepr::ToBytes;

use crate::{error::Error, json_print::JsonPrintable};

pub(crate) enum OutputOption {
    Muffle,
    ToFile { file_path: String },
    ToConsole,
}
pub(super) async fn handle_raw(
    node_address: &str,
    bytes: Vec<u8>,
    output_option: OutputOption,
) -> Result<Box<dyn JsonPrintable>, Error> {
    let response = send_raw_bytes(node_address, bytes).await?;
    match output_option {
        OutputOption::Muffle => Ok(Box::new("".to_string())),
        OutputOption::ToFile { file_path } => {
            let mut file = File::create(&file_path).map_err(|err| Error::FromFile {
                file_path: file_path.clone(),
                err,
            })?;
            let bytes = response.to_bytes().map_err(Error::Bytesrepr)?;
            file.write_all(&bytes).map_err(|err| Error::FromFile {
                file_path: file_path.clone(),
                err,
            })?;
            Ok(Box::new(format!(
                "Binary port produced response, response stored to file {file_path}"
            )))
        }
        OutputOption::ToConsole => {
            let bytes = response.to_bytes().map_err(Error::Bytesrepr)?;
            let hex_encoded = hex::encode(&bytes);
            Ok(Box::new(hex_encoded))
        }
    }
}
