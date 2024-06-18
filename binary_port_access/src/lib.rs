use std::io::Read;

use thiserror::Error;

use casper_binary_port::{
    ConsensusStatus, ConsensusValidatorChanges, EraIdentifier, InformationRequest,
    InformationRequestTag, LastProgress, NetworkName, NodeStatus, ReactorStateName, RewardResponse,
    TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::ToBytes, AvailableBlockRange, BlockHash, BlockHeader, BlockIdentifier,
    BlockSynchronizerStatus, ChainspecRawBytes, Digest, EraId, NextUpgrade, Peers, PublicKey,
    SignedBlock, TransactionHash,
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

pub async fn consensus_validator_changes(
    node_address: &str,
) -> Result<ConsensusValidatorChanges, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::ConsensusValidatorChanges,
        &[],
    )?;
    let response = communication::send_request(node_address, request).await?;
    let consensus_validator_changes =
        utils::parse_response::<ConsensusValidatorChanges>(response.response())?;
    return consensus_validator_changes.ok_or_else(|| {
        Error::Response("unable to read last consensus validator changes".to_string())
    });
}

pub async fn block_synchronizer_status(
    node_address: &str,
) -> Result<BlockSynchronizerStatus, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::BlockSynchronizerStatus,
        &[],
    )?;
    let response = communication::send_request(node_address, request).await?;
    let block_synchronizer_status =
        utils::parse_response::<BlockSynchronizerStatus>(response.response())?;
    return block_synchronizer_status.ok_or_else(|| {
        Error::Response("unable to read last block synchronizer status".to_string())
    });
}

pub async fn available_block_range(node_address: &str) -> Result<AvailableBlockRange, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::AvailableBlockRange, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let available_block_range = utils::parse_response::<AvailableBlockRange>(response.response())?;
    return available_block_range
        .ok_or_else(|| Error::Response("unable to read last available block range".to_string()));
}

pub async fn next_upgrade(node_address: &str) -> Result<Option<NextUpgrade>, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::NextUpgrade, &[])?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<NextUpgrade>(response.response())?)
}

pub async fn consensus_status(node_address: &str) -> Result<ConsensusStatus, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::ConsensusStatus, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let consensus_status = utils::parse_response::<ConsensusStatus>(response.response())?;
    return consensus_status
        .ok_or_else(|| Error::Response("unable to read last consensus status".to_string()));
}

pub async fn chainspec_raw_bytes(node_address: &str) -> Result<ChainspecRawBytes, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::ChainspecRawBytes, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let chainspec_raw_bytes = utils::parse_response::<ChainspecRawBytes>(response.response())?;
    return chainspec_raw_bytes
        .ok_or_else(|| Error::Response("unable to read last chainspec raw bytes".to_string()));
}

pub async fn node_status(node_address: &str) -> Result<NodeStatus, Error> {
    let request =
        information::make_information_get_request(InformationRequestTag::NodeStatus, &[])?;
    let response = communication::send_request(node_address, request).await?;
    let node_status = utils::parse_response::<NodeStatus>(response.response())?;
    return node_status
        .ok_or_else(|| Error::Response("unable to read last node status".to_string()));
}

async fn validator_reward_by_era_identifier(
    node_address: &str,
    validator_key: PublicKey,
    era_identifier: EraIdentifier,
) -> Result<Option<RewardResponse>, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::Reward,
        InformationRequest::Reward {
            era_identifier: Some(era_identifier),
            validator: Box::new(validator_key),
            delegator: None,
        }
        .to_bytes()?
        .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<RewardResponse>(
        response.response(),
    )?)
}

pub async fn validator_reward_by_era(
    node_address: &str,
    validator_key: PublicKey,
    era: EraId,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Era(era);
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

pub async fn validator_reward_by_block_height(
    node_address: &str,
    validator_key: PublicKey,
    block_height: u64,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Height(block_height));
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

pub async fn validator_reward_by_block_hash(
    node_address: &str,
    validator_key: PublicKey,
    block_hash: BlockHash,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Hash(block_hash));
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

async fn delegator_reward_by_era_identifier(
    node_address: &str,
    validator_key: PublicKey,
    delegator_key: PublicKey,
    era_identifier: EraIdentifier,
) -> Result<Option<RewardResponse>, Error> {
    let request = information::make_information_get_request(
        InformationRequestTag::Reward,
        InformationRequest::Reward {
            era_identifier: Some(era_identifier),
            validator: Box::new(validator_key),
            delegator: Some(Box::new(delegator_key)),
        }
        .to_bytes()?
        .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    Ok(utils::parse_response::<RewardResponse>(
        response.response(),
    )?)
}

pub async fn delegator_reward_by_era(
    node_address: &str,
    validator_key: PublicKey,
    delegator_key: PublicKey,
    era: EraId,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Era(era);
    delegator_reward_by_era_identifier(node_address, validator_key, delegator_key, era_identifier)
        .await
}

pub async fn delegator_reward_by_block_height(
    node_address: &str,
    validator_key: PublicKey,
    delegator_key: PublicKey,
    block_height: u64,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Height(block_height));
    delegator_reward_by_era_identifier(node_address, validator_key, delegator_key, era_identifier)
        .await
}

pub async fn delegator_reward_by_block_hash(
    node_address: &str,
    validator_key: PublicKey,
    delegator_key: PublicKey,
    block_hash: BlockHash,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Hash(block_hash));
    delegator_reward_by_era_identifier(node_address, validator_key, delegator_key, era_identifier)
        .await
}
