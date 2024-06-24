use casper_binary_port_access::try_accept_transaction;
use casper_types::TransactionV1;

use crate::{error::Error, json_print::JsonPrintable};

pub(super) async fn handle_transaction_request(
    node_address: &str,
    transaction_file: &str,
) -> Result<Box<dyn JsonPrintable>, Error> {
    let transaction_raw = std::fs::read(transaction_file)?;
    let transaction: TransactionV1 = serde_json::from_slice(&transaction_raw)?;

    try_accept_transaction(node_address, transaction.into()).await?;
    Ok(Box::new("Transaction accepted for inclusion".to_string()))
}
