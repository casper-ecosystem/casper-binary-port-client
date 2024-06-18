use std::fmt;

pub(crate) const EMPTY_STR: &str = "[EMPTY]";

// TODO[RC]: All these should output proper JSON data.

pub(crate) fn print_response_opt<T: fmt::Debug>(opt: Option<T>) {
    match opt {
        Some(val) => println!("{:#?}", val),
        None => println!("{EMPTY_STR}"),
    }
}

pub(crate) fn print_response<T: fmt::Debug>(resp: T) {
    println!("{:#?}", resp)
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
