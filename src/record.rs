use casper_binary_port::{BinaryRequest, BinaryResponseAndRequest, GetRequest, RecordId};

use crate::{
    communication::send_request,
    error::Error,
    utils::{print_hex_payload, EMPTY_STR},
};

pub(super) async fn handle_record_request(record_id: u16, key: &str) -> Result<(), Error> {
    let _: RecordId = record_id.try_into().map_err(Error::Record)?;
    let key = hex::decode(key)?;

    let request = make_record_get_request(record_id, key)?;
    let response = send_request(request).await?;
    handle_record_response(&response);

    Ok(())
}

fn handle_record_response(response: &BinaryResponseAndRequest) {
    print_hex_payload(response.response().payload())
}

fn make_record_get_request(tag: u16, key: Vec<u8>) -> Result<BinaryRequest, Error> {
    Ok(BinaryRequest::Get(GetRequest::Record {
        record_type_tag: tag,
        key,
    }))
}
