use casper_binary_port_access::{
    available_block_range, block_header_by_hash, block_header_by_height, block_synchronizer_status,
    chainspec_raw_bytes, consensus_status, consensus_validator_changes,
    delegator_reward_by_block_hash, delegator_reward_by_block_height, delegator_reward_by_era,
    last_progress, latest_block_header, latest_signed_block, latest_switch_block_header,
    network_name, next_upgrade, node_status, peers, protocol_version, reactor_state,
    signed_block_by_hash, signed_block_by_height, transaction_by_hash, uptime,
    validator_reward_by_block_hash, validator_reward_by_block_height, validator_reward_by_era,
};
use casper_types::{AsymmetricType, BlockHash, DeployHash, Digest, PublicKey, TransactionHash};
use clap::{command, ArgGroup, Subcommand};

use crate::{error::Error, json_print::JsonPrintable};

#[derive(Debug, Subcommand)]
pub(crate) enum Information {
    /// Retrieve block header by height or hash.
    BlockHeader {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Retrieve block with signatures by height or hash.
    SignedBlock {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Retrieve a transaction with approvals and execution info for a given hash.
    Transaction {
        /// Hash of the transaction to retrieve.
        #[clap(long)]
        hash: String,
        /// Whether to return the deploy with the finalized approvals substituted.
        #[clap(long, short)]
        with_finalized_approvals: bool,
        /// Whether to return the legacy deploy or the new transaction.
        #[clap(long, short)]
        legacy: bool,
    },
    /// Returns connected peers.
    Peers,
    /// Read node uptime.
    Uptime,
    /// Returns last progress of the sync process.
    LastProgress,
    /// Returns current state of the main reactor.
    ReactorState,
    /// Returns network name.
    NetworkName,
    /// Returns consensus validator changes.
    ConsensusValidatorChanges,
    /// Returns status of the BlockSynchronizer.
    BlockSynchronizerStatus,
    /// Available block range request.
    AvailableBlockRange,
    /// Next upgrade request.
    NextUpgrade,
    /// Consensus status request.
    ConsensusStatus,
    /// Retrieve raw chainspec bytes.
    ChainspecRawBytes,
    /// Read node status.
    NodeStatus,
    /// Latest switch block header request.
    LatestSwitchBlockHeader,
    /// Reward for a validator or a delegator in a specific era identified by either era number or block hash or block height.
    #[command(group(
        ArgGroup::new("validator_data")
            .required(true)
            .args(&["validator_key", "validator_key_file"])
    ))]
    Reward {
        #[clap(
            long,
            short,
            conflicts_with = "block_hash",
            conflicts_with = "block_height"
        )]
        era: Option<u64>,
        #[clap(long, conflicts_with = "block_height", conflicts_with = "era")]
        block_hash: Option<String>,
        #[clap(long, conflicts_with = "block_hash", conflicts_with = "era")]
        block_height: Option<u64>,
        #[clap(long, conflicts_with = "validator_key_file")]
        validator_key: Option<String>,
        #[clap(long, short, conflicts_with = "validator_key")]
        validator_key_file: Option<String>,
        #[clap(long, conflicts_with = "delegator_key_file")]
        delegator_key: Option<String>,
        #[clap(long, short, conflicts_with = "delegator_key")]
        delegator_key_file: Option<String>,
    },
    /// Current protocol version.
    ProtocolVersion,
}

pub(super) async fn handle_information_request(
    node_address: &str,
    req: Information,
) -> Result<Box<dyn JsonPrintable>, Error> {
    Ok(match req {
        Information::BlockHeader { hash, height } => Box::new(match (hash, height) {
            (None, None) => latest_block_header(node_address).await?,
            (None, Some(height)) => block_header_by_height(node_address, height).await?,
            (Some(hash), None) => {
                let digest = casper_types::Digest::from_hex(hash)?;
                block_header_by_hash(node_address, BlockHash::new(digest)).await?
            }
            (Some(_), Some(_)) => return Err(Error::EitherHashOrHeightRequired),
        }),
        Information::SignedBlock { hash, height } => Box::new(match (hash, height) {
            (None, None) => latest_signed_block(node_address).await?,
            (None, Some(height)) => signed_block_by_height(node_address, height).await?,
            (Some(hash), None) => {
                let digest = casper_types::Digest::from_hex(hash)?;
                signed_block_by_hash(node_address, BlockHash::new(digest)).await?
            }
            (Some(_), Some(_)) => return Err(Error::EitherHashOrHeightRequired),
        }),
        Information::Transaction {
            hash,
            with_finalized_approvals,
            legacy,
        } => {
            let digest = Digest::from_hex(hash)?;
            let transaction_hash = if legacy {
                TransactionHash::Deploy(DeployHash::from(digest))
            } else {
                TransactionHash::from_raw(digest.value())
            };
            Box::new(
                transaction_by_hash(node_address, transaction_hash, with_finalized_approvals)
                    .await?,
            )
        }
        Information::Peers => Box::new(peers(node_address).await?),
        Information::Uptime => Box::new(uptime(node_address).await?),
        Information::LastProgress => Box::new(last_progress(node_address).await?),
        Information::ReactorState => Box::new(reactor_state(node_address).await?),
        Information::NetworkName => Box::new(network_name(node_address).await?),
        Information::ConsensusValidatorChanges => {
            Box::new(consensus_validator_changes(node_address).await?)
        }
        Information::BlockSynchronizerStatus => {
            Box::new(block_synchronizer_status(node_address).await?)
        }
        Information::AvailableBlockRange => Box::new(available_block_range(node_address).await?),
        Information::NextUpgrade => Box::new(next_upgrade(node_address).await?),
        Information::ConsensusStatus => Box::new(consensus_status(node_address).await?),
        Information::ChainspecRawBytes => Box::new(chainspec_raw_bytes(node_address).await?),
        Information::NodeStatus => Box::new(node_status(node_address).await?),
        Information::LatestSwitchBlockHeader => {
            Box::new(latest_switch_block_header(node_address).await?)
        }
        Information::Reward {
            era,
            block_hash: hash,
            block_height: height,
            validator_key,
            validator_key_file,
            delegator_key,
            delegator_key_file,
        } => {
            let validator_key = match (validator_key, validator_key_file) {
                (None, None) => return Err(Error::ValidatorKeyRequired),
                (None, Some(validator_key_file)) => PublicKey::from_file(validator_key_file)?,
                (Some(validator_key), None) => PublicKey::from_hex(validator_key)?,
                (Some(_), Some(_)) => return Err(Error::EitherKeyOrKeyFileRequired),
            };

            let delegator_key = match (delegator_key, delegator_key_file) {
                (None, None) => None,
                (None, Some(delegator_key_file)) => Some(PublicKey::from_file(delegator_key_file)?),
                (Some(delegator_key), None) => Some(PublicKey::from_hex(delegator_key)?),
                (Some(_), Some(_)) => return Err(Error::EitherKeyOrKeyFileRequired),
            };

            match (era, hash, height) {
                (Some(era), None, None) => Box::new(if let Some(delegator_key) = delegator_key {
                    delegator_reward_by_era(node_address, validator_key, delegator_key, era.into())
                        .await?
                } else {
                    validator_reward_by_era(node_address, validator_key, era.into()).await?
                }),
                (None, Some(hash), None) => Box::new(if let Some(delegator_key) = delegator_key {
                    delegator_reward_by_block_hash(
                        node_address,
                        validator_key,
                        delegator_key,
                        Digest::from_hex(hash)?.into(),
                    )
                    .await?
                } else {
                    validator_reward_by_block_hash(
                        node_address,
                        validator_key,
                        Digest::from_hex(hash)?.into(),
                    )
                    .await?
                }),
                (None, None, Some(height)) => {
                    Box::new(if let Some(delegator_key) = delegator_key {
                        delegator_reward_by_block_height(
                            node_address,
                            validator_key,
                            delegator_key,
                            height,
                        )
                        .await?
                    } else {
                        validator_reward_by_block_height(node_address, validator_key, height)
                            .await?
                    })
                }
                _ => return Err(Error::InvalidEraIdentifier),
            }
        }
        Information::ProtocolVersion => Box::new(protocol_version(node_address).await?),
    })
}
