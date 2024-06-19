use crate::json_print::{serialize_to_json, JsonPrintable};

pub(crate) const EMPTY_STR: &str = "[EMPTY]";

pub(crate) fn print_response(resp: Box<dyn JsonPrintable>) {
    let json = serialize_to_json(&*resp).unwrap();
    println!("{}", json);
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
