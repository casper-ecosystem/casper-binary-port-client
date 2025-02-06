#![deny(missing_docs)]
//! This crate provides a high-level API for interacting with a Casper node's binary port interface.

mod communication;
mod error;
mod utils;

#[cfg(not(target_arch = "wasm32"))]
use casper_binary_port::BinaryResponse;
use casper_binary_port::{
    Command, ConsensusStatus, ConsensusValidatorChanges, EraIdentifier, GlobalStateQueryResult,
    InformationRequestTag, LastProgress, NetworkName, NodeStatus, ReactorStateName, RecordId,
    RewardResponse, SpeculativeExecutionResult, TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::ToBytes, AvailableBlockRange, BlockHash, BlockHeader, BlockIdentifier,
    BlockSynchronizerStatus, BlockWithSignatures, ChainspecRawBytes, Digest, EraId,
    GlobalStateIdentifier, Key, NextUpgrade, Peers, ProtocolVersion, PublicKey, Transaction,
    TransactionHash,
};
pub use communication::common::initialize_request_id;
use communication::common::parse_response;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use communication::common::send_request;
#[cfg(target_arch = "wasm32")]
pub(crate) use communication::wasm32::send_request;

pub use error::Error;
use thiserror::Error;
use utils::{
    check_error_code, delegator_reward_by_era_identifier, global_state_item_by_state_identifier,
    make_information_get_request, validator_reward_by_era_identifier,
};

/// Returns the latest switch block header.
pub async fn latest_switch_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
    let request =
        make_information_get_request(InformationRequestTag::LatestSwitchBlockHeader, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

/// Returns the latest block header.
pub async fn latest_block_header(node_address: &str) -> Result<Option<BlockHeader>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

/// Returns the block header at the given height.
pub async fn block_header_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

/// Returns the block header with the given hash.
pub async fn block_header_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<BlockHeader>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = make_information_get_request(
        InformationRequestTag::BlockHeader,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockHeader>(response.response())
}

/// Returns the latest block along with signatures.
pub async fn latest_block_with_signatures(
    node_address: &str,
) -> Result<Option<BlockWithSignatures>, Error> {
    let block_id: Option<BlockIdentifier> = None;
    let request = make_information_get_request(
        InformationRequestTag::BlockWithSignatures,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockWithSignatures>(response.response())
}

/// Returns the block at the given height along with signatures.
pub async fn block_with_signatures_by_height(
    node_address: &str,
    height: u64,
) -> Result<Option<BlockWithSignatures>, Error> {
    let block_id = Some(BlockIdentifier::Height(height));
    let request = make_information_get_request(
        InformationRequestTag::BlockWithSignatures,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockWithSignatures>(response.response())
}

/// Returns the block with the given hash along with signatures.
pub async fn block_with_signatures_by_hash(
    node_address: &str,
    hash: BlockHash,
) -> Result<Option<BlockWithSignatures>, Error> {
    let block_id = Some(BlockIdentifier::Hash(hash));
    let request = make_information_get_request(
        InformationRequestTag::BlockWithSignatures,
        block_id.to_bytes()?.as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<BlockWithSignatures>(response.response())
}

/// Returns the transaction with the given hash. If `with_finalized_approvals` is `false`, the
/// approvals that were originally received by the node are returned. Otherwise, the substituted
/// approvals are returned.
pub async fn transaction_by_hash(
    node_address: &str,
    hash: TransactionHash,
    with_finalized_approvals: bool,
) -> Result<Option<TransactionWithExecutionInfo>, Error> {
    let request = make_information_get_request(
        InformationRequestTag::Transaction,
        hash.to_bytes()?
            .into_iter()
            .chain(with_finalized_approvals.to_bytes()?.into_iter())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<TransactionWithExecutionInfo>(response.response())
}

/// Returns the peer list.
pub async fn peers(node_address: &str) -> Result<Peers, Error> {
    let request = make_information_get_request(InformationRequestTag::Peers, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let peers = parse_response::<Peers>(response.response())?;
    peers.ok_or_else(|| Error::Response("unable to read peers".to_string()))
}

/// Returns the node uptime.
pub async fn uptime(node_address: &str) -> Result<Uptime, Error> {
    let request = make_information_get_request(InformationRequestTag::Uptime, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let uptime = parse_response::<Uptime>(response.response())?;
    uptime.ok_or_else(|| Error::Response("unable to read uptime".to_string()))
}

/// Returns the last progress as recorded by the node.
pub async fn last_progress(node_address: &str) -> Result<LastProgress, Error> {
    let request = make_information_get_request(InformationRequestTag::LastProgress, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let last_progress = parse_response::<LastProgress>(response.response())?;
    last_progress.ok_or_else(|| Error::Response("unable to read last progress".to_string()))
}

/// Returns the current reactor state.
pub async fn reactor_state(node_address: &str) -> Result<ReactorStateName, Error> {
    let request = make_information_get_request(InformationRequestTag::ReactorState, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let reactor_state = parse_response::<ReactorStateName>(response.response())?;
    reactor_state.ok_or_else(|| Error::Response("unable to read last reactor state".to_string()))
}

/// Returns the network (chain) name.
pub async fn network_name(node_address: &str) -> Result<NetworkName, Error> {
    let request = make_information_get_request(InformationRequestTag::NetworkName, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let network_name = parse_response::<NetworkName>(response.response())?;
    network_name.ok_or_else(|| Error::Response("unable to read last network name".to_string()))
}

/// Returns the last consensus validator changes.
pub async fn consensus_validator_changes(
    node_address: &str,
) -> Result<ConsensusValidatorChanges, Error> {
    let request =
        make_information_get_request(InformationRequestTag::ConsensusValidatorChanges, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let consensus_validator_changes =
        parse_response::<ConsensusValidatorChanges>(response.response())?;
    consensus_validator_changes.ok_or_else(|| {
        Error::Response("unable to read last consensus validator changes".to_string())
    })
}

/// Returns the status of the block synchronizer.
pub async fn block_synchronizer_status(
    node_address: &str,
) -> Result<BlockSynchronizerStatus, Error> {
    let request =
        make_information_get_request(InformationRequestTag::BlockSynchronizerStatus, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let block_synchronizer_status = parse_response::<BlockSynchronizerStatus>(response.response())?;
    block_synchronizer_status
        .ok_or_else(|| Error::Response("unable to read last block synchronizer status".to_string()))
}

/// Returns the available block range.
pub async fn available_block_range(node_address: &str) -> Result<AvailableBlockRange, Error> {
    let request = make_information_get_request(InformationRequestTag::AvailableBlockRange, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let available_block_range = parse_response::<AvailableBlockRange>(response.response())?;
    available_block_range
        .ok_or_else(|| Error::Response("unable to read last available block range".to_string()))
}

/// Returns the information about the next upgrade point.
pub async fn next_upgrade(node_address: &str) -> Result<Option<NextUpgrade>, Error> {
    let request = make_information_get_request(InformationRequestTag::NextUpgrade, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<NextUpgrade>(response.response())
}

/// Returns the current status of the consensus.
pub async fn consensus_status(node_address: &str) -> Result<ConsensusStatus, Error> {
    let request = make_information_get_request(InformationRequestTag::ConsensusStatus, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let consensus_status = parse_response::<ConsensusStatus>(response.response())?;
    consensus_status
        .ok_or_else(|| Error::Response("unable to read last consensus status".to_string()))
}

/// Returns the raw bytes of the current chainspec along with the optional information about the
/// genesis accounts and global state configuration files.
pub async fn chainspec_raw_bytes(node_address: &str) -> Result<ChainspecRawBytes, Error> {
    let request = make_information_get_request(InformationRequestTag::ChainspecRawBytes, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let chainspec_raw_bytes = parse_response::<ChainspecRawBytes>(response.response())?;
    chainspec_raw_bytes
        .ok_or_else(|| Error::Response("unable to read last chainspec raw bytes".to_string()))
}

/// Returns the node status.
pub async fn node_status(node_address: &str) -> Result<NodeStatus, Error> {
    let request = make_information_get_request(InformationRequestTag::NodeStatus, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let node_status = parse_response::<NodeStatus>(response.response())?;
    node_status.ok_or_else(|| Error::Response("unable to read last node status".to_string()))
}

/// Returns the reward for the given validator at the given era.
pub async fn validator_reward_by_era(
    node_address: &str,
    validator_key: PublicKey,
    era: EraId,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Era(era);
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

/// Returns the reward for the given validator at the era containing the block at given height.
pub async fn validator_reward_by_block_height(
    node_address: &str,
    validator_key: PublicKey,
    block_height: u64,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Height(block_height));
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

/// Returns the reward for the given validator at the era containing the block with given hash.
pub async fn validator_reward_by_block_hash(
    node_address: &str,
    validator_key: PublicKey,
    block_hash: BlockHash,
) -> Result<Option<RewardResponse>, Error> {
    let era_identifier = EraIdentifier::Block(BlockIdentifier::Hash(block_hash));
    validator_reward_by_era_identifier(node_address, validator_key, era_identifier).await
}

/// Returns the reward for the given delegator at the given era.
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

/// Returns the reward for the given delegator at the era containing the block at given height.
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

/// Returns the reward for the given delegator at the era containing the block with given hash.
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

// TODO: Add function for getting the validator and delegator reward w/o specifying the era identifier.

/// Returns the record with a given key from the given database. Response contains raw bytes
/// as obtained from the node storage.
/// ```
/// | record id | database                      |
/// |-----------|-------------------------------|
/// | 0         | BlockHeader                   |
/// | 1         | BlockBody                     |
/// | 2         | ApprovalsHashes               |
/// | 3         | BlockMetadata                 |
/// | 4         | Transaction                   |
/// | 5         | ExecutionResult               |
/// | 6         | Transfer                      |
/// | 7         | FinalizedTransactionApprovals |
/// ```
pub async fn read_record(
    node_address: &str,
    record_id: RecordId,
    key: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = utils::make_record_request(record_id, key);
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    Ok(response.response().payload().into())
}

/// Returns an item at the given key from the global state. The most recent state root hash is used to obtain the data.
pub async fn global_state_item(
    node_address: &str,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    global_state_item_by_state_identifier(node_address, None, key, path).await
}

/// Returns an item at the given key from the global state. The given state root hash is used
/// to obtain the data.
pub async fn global_state_item_by_state_root_hash(
    node_address: &str,
    state_root_hash: Digest,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    let state_identifier = GlobalStateIdentifier::StateRootHash(state_root_hash);
    global_state_item_by_state_identifier(node_address, Some(state_identifier), key, path).await
}

/// Returns an item at the given key from the global state. The state root hash associated with
/// the block with given hash is used to obtain the data.
pub async fn global_state_item_by_block_hash(
    node_address: &str,
    block_hash: BlockHash,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    let state_identifier = GlobalStateIdentifier::BlockHash(block_hash);
    global_state_item_by_state_identifier(node_address, Some(state_identifier), key, path).await
}

/// Returns an item at the given key from the global state. The state root hash associated with
/// the block with given height is used to obtain the data.
pub async fn global_state_item_by_block_height(
    node_address: &str,
    block_height: u64,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    let state_identifier = GlobalStateIdentifier::BlockHeight(block_height);
    global_state_item_by_state_identifier(node_address, Some(state_identifier), key, path).await
}

/// Sends a transaction to the node for inclusion.
pub async fn try_accept_transaction(
    node_address: &str,
    transaction: Transaction,
) -> Result<(), Error> {
    let request = Command::TryAcceptTransaction { transaction };
    let response = send_request(node_address, request).await?;
    check_error_code(&response)
}

/// Sends a transaction to the node for speculative execution.
pub async fn try_speculative_execution(
    node_address: &str,
    transaction: Transaction,
) -> Result<SpeculativeExecutionResult, Error> {
    let request = Command::TrySpeculativeExec { transaction };
    let response = send_request(node_address, request).await?;

    check_error_code(&response)?;

    let speculative_execution_result =
        parse_response::<SpeculativeExecutionResult>(response.response())?;
    speculative_execution_result
        .ok_or_else(|| Error::Response("unable to read speculative execution result".to_string()))
}

/// Returns the protocol version.
pub async fn protocol_version(node_address: &str) -> Result<ProtocolVersion, Error> {
    let request = make_information_get_request(InformationRequestTag::ProtocolVersion, &[])?;
    let response = send_request(node_address, request).await?;
    check_error_code(&response)?;
    let protocol_version = parse_response::<ProtocolVersion>(response.response())?;
    protocol_version.ok_or_else(|| Error::Response("unable to read protocol version".to_string()))
}

/// Sends raw bytes to the network, does no validation or assumption on structure
#[cfg(not(target_arch = "wasm32"))]
pub async fn send_raw_bytes(
    node_address: &str,
    raw_bytes: Vec<u8>,
) -> Result<BinaryResponse, Error> {
    utils::send_raw_bytes(node_address, raw_bytes).await
}
