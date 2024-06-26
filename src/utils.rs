use crate::json_print::{serialize_to_json, JsonPrintable};

pub(crate) fn print_response(resp: Box<dyn JsonPrintable>) {
    let json = serialize_to_json(&*resp).expect("unable to serialize response to JSON");
    println!("{}", json);
}
