use std::fmt;

use casper_types::ProtocolVersion;

pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);
pub(crate) const EMPTY_STR: &str = "[EMPTY]";

pub(crate) fn print_option<T: fmt::Debug>(opt: Option<T>) {
    match opt {
        Some(val) => println!("{:#?}", val),
        None => println!("{EMPTY_STR}"),
    }
}

pub(crate) fn print_hex_payload(payload: &[u8]) {
    let len = payload.len();
    if len > 0 {
        let hex = hex::encode(payload);
        // TODO: Print length in verbose mode only.
        println!("{len} bytes:");
        println!("{hex}")
    } else {
        println!("{EMPTY_STR}");
    }
}
