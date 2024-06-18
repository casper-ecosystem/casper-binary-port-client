use casper_binary_port_access::read_record;

use crate::{error::Error, utils::print_hex_payload};

pub(super) async fn handle_record_request(
    node_address: &str,
    record_id: u16,
    key: &str,
) -> Result<(), Error> {
    let record_id = record_id.try_into().map_err(Error::Record)?;
    let key = hex::decode(key)?;

    let response = read_record(node_address, record_id, key.as_slice()).await?;
    print_hex_payload(response.as_slice());

    Ok(())
}
