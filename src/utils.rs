use std::fmt;

use casper_types::ProtocolVersion;

pub(crate) const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::from_parts(2, 0, 0);
pub(crate) const EMPTY_STR: &str = "[EMPTY]";

pub(crate) fn debug_print_option<T: fmt::Debug>(opt: Option<T>) {
    match opt {
        Some(val) => println!("{:#?}", val),
        None => println!("{EMPTY_STR}"),
    }
}
