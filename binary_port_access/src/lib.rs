use thiserror::Error;

use casper_binary_port::InformationRequestTag;
use casper_types::{bytesrepr::ToBytes, BlockHash, BlockHeader, BlockIdentifier, Digest, SignedBlock};

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

pub async fn latest_block_header(
    node_address: &str,
) -> Result<Option<BlockHeader>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = information::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<BlockHeader>(response.response())?)
}

pub async fn block_header_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = information::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<BlockHeader>(response.response())?)
}

pub async fn block_header_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = information::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<BlockHeader>(response.response())?)
}

pub async fn latest_signed_block(
    node_address: &str,
) -> Result<Option<SignedBlock>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = information::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<SignedBlock>(response.response())?)
}

pub async fn signed_block_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<SignedBlock>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = information::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<SignedBlock>(response.response())?)
}

pub async fn signed_block_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<SignedBlock>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = information::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<SignedBlock>(response.response())?)
}
