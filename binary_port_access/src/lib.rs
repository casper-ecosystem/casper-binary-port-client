use thiserror::Error;

use casper_binary_port::InformationRequestTag;
use casper_types::BlockHeader;

mod communication;
mod error;
mod information;
mod utils;

pub use error::Error;

pub async fn latest_switch_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::LatestSwitchBlockHeader,
        &[],
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<BlockHeader>(response.response())?)
}
