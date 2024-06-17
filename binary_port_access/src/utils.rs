use casper_binary_port::{BinaryResponse, PayloadEntity};
use casper_types::bytesrepr::{self, FromBytes};

use crate::Error;

pub(crate) fn parse_response<A: FromBytes + PayloadEntity>(
    response: &BinaryResponse,
) -> Result<Option<A>, Error> {
    match response.returned_data_type_tag() {
        Some(found) if found == u8::from(A::PAYLOAD_TYPE) => {
            // TODO: Verbose: print length of payload
            Ok(Some(bytesrepr::deserialize_from_slice(response.payload())?))
        }
        Some(other) => Err(Error::Response(format!(
            "unsupported response type: {other}"
        ))),
        _ => Ok(None),
    }
}
