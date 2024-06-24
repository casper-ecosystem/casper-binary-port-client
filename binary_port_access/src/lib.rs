use communication::parse_response;
use thiserror::Error;

use casper_binary_port::{
    BinaryRequest, ConsensusStatus, ConsensusValidatorChanges, EraIdentifier, GetRequest,
    GlobalStateQueryResult, GlobalStateRequest, InformationRequestTag, LastProgress, NetworkName,
    NodeStatus, ReactorStateName, RecordId, RewardResponse, SpeculativeExecutionResult,
    TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::ToBytes, AvailableBlockRange, BlockHash, BlockHeader, BlockIdentifier,
    BlockSynchronizerStatus, ChainspecRawBytes, Digest, EraId, GlobalStateIdentifier, Key,
    NextUpgrade, Peers, PublicKey, SignedBlock, Transaction, TransactionHash,
};

mod communication;
mod error;
pub(crate) mod utils;

pub use error::Error;
use utils::{
    check_error_code, delegator_reward_by_era_identifier, validator_reward_by_era_identifier,
};

pub async fn latest_switch_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
    let request =
        utils::make_information_get_request(InformationRequestTag::LatestSwitchBlockHeader, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

pub async fn latest_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = utils::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

pub async fn block_header_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = utils::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

pub async fn block_header_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = utils::make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

pub async fn latest_signed_block(node_address: &str) -> Result<Option<SignedBlock>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = utils::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<SignedBlock>(response.response())
}

pub async fn signed_block_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<SignedBlock>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = utils::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<SignedBlock>(response.response())
}

pub async fn signed_block_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<SignedBlock>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = utils::make_information_get_request(
        InformationRequestTag::SignedBlock,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<SignedBlock>(response.response())
}

pub async fn transaction_by_hash(
    node_address: &str,
    hash: TransactionHash,
    with_finalized_approvals: bool,
) -> Result<Option<TransactionWithExecutionInfo>, Error> {
    let request = utils::make_information_get_request(
        InformationRequestTag::Transaction,
        hash.to_bytes()?
            .into_iter()
            .chain(with_finalized_approvals.to_bytes()?.into_iter())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<TransactionWithExecutionInfo>(response.response())
}

pub async fn peers(node_address: &str) -> Result<Peers, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::Peers, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let peers = parse_response::<Peers>(response.response())?;
    peers.ok_or_else(|| Error::Response("unable to read peers".to_string()))
}

pub async fn uptime(node_address: &str) -> Result<Uptime, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::Uptime, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let uptime = parse_response::<Uptime>(response.response())?;
    uptime.ok_or_else(|| Error::Response("unable to read uptime".to_string()))
}

pub async fn last_progress(node_address: &str) -> Result<LastProgress, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::LastProgress, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let last_progress = parse_response::<LastProgress>(response.response())?;
    last_progress.ok_or_else(|| Error::Response("unable to read last progress".to_string()))
}

pub async fn reactor_state(node_address: &str) -> Result<ReactorStateName, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::ReactorState, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let reactor_state = parse_response::<ReactorStateName>(response.response())?;
    reactor_state.ok_or_else(|| Error::Response("unable to read last reactor state".to_string()))
}

pub async fn network_name(node_address: &str) -> Result<NetworkName, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::NetworkName, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let network_name = parse_response::<NetworkName>(response.response())?;
    network_name.ok_or_else(|| Error::Response("unable to read last network name".to_string()))
}

pub async fn consensus_validator_changes(
    node_address: &str,
) -> Result<ConsensusValidatorChanges, Error> {
    let request =
        utils::make_information_get_request(InformationRequestTag::ConsensusValidatorChanges, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let consensus_validator_changes =
        parse_response::<ConsensusValidatorChanges>(response.response())?;
    consensus_validator_changes.ok_or_else(|| {
        Error::Response("unable to read last consensus validator changes".to_string())
    })
}

pub async fn block_synchronizer_status(
    node_address: &str,
) -> Result<BlockSynchronizerStatus, Error> {
    let request =
        utils::make_information_get_request(InformationRequestTag::BlockSynchronizerStatus, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let block_synchronizer_status = parse_response::<BlockSynchronizerStatus>(response.response())?;
    block_synchronizer_status
        .ok_or_else(|| Error::Response("unable to read last block synchronizer status".to_string()))
}

pub async fn available_block_range(node_address: &str) -> Result<AvailableBlockRange, Error> {
    let request =
        utils::make_information_get_request(InformationRequestTag::AvailableBlockRange, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let available_block_range = parse_response::<AvailableBlockRange>(response.response())?;
    available_block_range
        .ok_or_else(|| Error::Response("unable to read last available block range".to_string()))
}

pub async fn next_upgrade(node_address: &str) -> Result<Option<NextUpgrade>, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::NextUpgrade, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<NextUpgrade>(response.response())
}

pub async fn consensus_status(node_address: &str) -> Result<ConsensusStatus, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::ConsensusStatus, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let consensus_status = parse_response::<ConsensusStatus>(response.response())?;
    consensus_status
        .ok_or_else(|| Error::Response("unable to read last consensus status".to_string()))
}

pub async fn chainspec_raw_bytes(node_address: &str) -> Result<ChainspecRawBytes, Error> {
    let request =
        utils::make_information_get_request(InformationRequestTag::ChainspecRawBytes, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let chainspec_raw_bytes = parse_response::<ChainspecRawBytes>(response.response())?;
    chainspec_raw_bytes
        .ok_or_else(|| Error::Response("unable to read last chainspec raw bytes".to_string()))
}

pub async fn node_status(node_address: &str) -> Result<NodeStatus, Error> {
    let request = utils::make_information_get_request(InformationRequestTag::NodeStatus, &[])?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    let node_status = parse_response::<NodeStatus>(response.response())?;
    node_status.ok_or_else(|| Error::Response("unable to read last node status".to_string()))
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

pub async fn read_record(
    node_address: &str,
    record_id: RecordId,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = utils::make_record_request(record_id, key);
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    Ok(response.response().payload().into())
}

pub async fn global_state_item_by_state_root_hash(
    node_address: &str,
    state_root_hash: Digest,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    let state_identifier = GlobalStateIdentifier::StateRootHash(state_root_hash);
    let global_state_request = GlobalStateRequest::Item {
        state_identifier: Some(state_identifier),
        base_key: key,
        path,
    };
    let request = BinaryRequest::Get(GetRequest::State(Box::new(global_state_request)));

    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<GlobalStateQueryResult>(response.response())
}

pub async fn try_accept_transaction(
    node_address: &str,
    transaction: Transaction,
) -> Result<(), Error> {
    let request = BinaryRequest::TryAcceptTransaction { transaction };
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)
}

pub async fn try_speculative_execution(
    node_address: &str,
    transaction: Transaction,
) -> Result<SpeculativeExecutionResult, Error> {
    let request = BinaryRequest::TrySpeculativeExec { transaction };
    let response = communication::send_request(node_address, request).await?;

    check_error_code(&response)?;

    let speculative_execution_result =
        parse_response::<SpeculativeExecutionResult>(response.response())?;
    speculative_execution_result
        .ok_or_else(|| Error::Response("unable to read speculative execution result".to_string()))
}
