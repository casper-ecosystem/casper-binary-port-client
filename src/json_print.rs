use erased_serde::Serialize as ErasedSerialize;
use serde::Serialize;

pub(crate) trait JsonPrintable {
    fn as_serialize(&self) -> &dyn ErasedSerialize;
}

impl<T> JsonPrintable for T
where
    T: Serialize,
{
    fn as_serialize(&self) -> &dyn ErasedSerialize {
        self
    }
}

pub(crate) fn serialize_to_json(obj: &dyn JsonPrintable) -> serde_json::Result<String> {
    let serializable = obj.as_serialize();
    serde_json::to_string_pretty(serializable)
}
