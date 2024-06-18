use std::io::Read;

use thiserror::Error;

use casper_binary_port::{
    InformationRequestTag, LastProgress, NetworkName, ReactorStateName,
    TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::ToBytes, BlockHash, BlockHeader, BlockIdentifier, Digest, Peers, SignedBlock,
    TransactionHash,
};

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

pub async fn latest_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
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

pub async fn latest_signed_block(node_address: &str) -> Result<Option<SignedBlock>, Error> {
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

pub async fn transaction_by_hash(
    node_address: &str,
    hash: TransactionHash,
    with_finalized_approvals: bool,
) -> Result<Option<TransactionWithExecutionInfo>, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::Transaction,
        hash.to_bytes()?
            .into_iter()
            .chain(with_finalized_approvals.to_bytes()?.into_iter())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<TransactionWithExecutionInfo>(
        response.response(),
    )?)
}

pub async fn peers(node_address: &str) -> Result<Peers, Error> {
    let request = information::make_information_get_request(InformationRequestTag::Peers, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let peers = utils::parse_response::<Peers>(response.response())?;
    return peers.ok_or_else(|| Error::Response("unable to read peers".to_string()));
}

pub async fn uptime(node_address: &str) -> Result<Uptime, Error> {
    let request = information::make_information_get_request(InformationRequestTag::Uptime, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let uptime = utils::parse_response::<Uptime>(response.response())?;
    return uptime.ok_or_else(|| Error::Response("unable to read uptime".to_string()));
}

pub async fn last_progress(node_address: &str) -> Result<LastProgress, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::LastProgress, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let last_progress = utils::parse_response::<LastProgress>(response.response())?;
    return last_progress
        .ok_or_else(|| Error::Response("unable to read last progress".to_string()));
}

pub async fn reactor_state(node_address: &str) -> Result<ReactorStateName, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::ReactorState, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let reactor_state = utils::parse_response::<ReactorStateName>(response.response())?;
    return reactor_state
        .ok_or_else(|| Error::Response("unable to read last reactor state".to_string()));
}

pub async fn network_name(node_address: &str) -> Result<NetworkName, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::NetworkName, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let network_name = utils::parse_response::<NetworkName>(response.response())?;
    return network_name
        .ok_or_else(|| Error::Response("unable to read last network name".to_string()));
}
