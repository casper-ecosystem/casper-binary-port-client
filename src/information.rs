use casper_binary_port::{
    BinaryRequest, BinaryResponse, BinaryResponseAndRequest, ConsensusStatus,
    ConsensusValidatorChanges, EraIdentifier, InformationRequest, InformationRequestTag,
    LastProgress, NetworkName, NodeStatus, PayloadEntity, ReactorStateName, RewardResponse,
    TransactionWithExecutionInfo, Uptime,
};
use casper_binary_port_access::latest_switch_block_header;
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    AsymmetricType, AvailableBlockRange, BlockHash, BlockHeader, BlockIdentifier,
    BlockSynchronizerStatus, ChainspecRawBytes, DeployHash, Digest, EraId, NextUpgrade, Peers,
    PublicKey, SignedBlock, TransactionHash,
};
use clap::{command, ArgGroup, Subcommand};

use crate::{communication::send_request, error::Error, utils::print_option};

#[derive(Debug, Subcommand)]
pub(crate) enum Information {
    /// Retrieve block header by height or hash.
    #[command(group(
        ArgGroup::new("block_id")
            .required(true)
            .args(&["hash", "height"])
    ))]
    BlockHeader {
        #[clap(long, conflicts_with = "height")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash")]
        height: Option<u64>,
    },
    /// Retrieve block with signatures by height or hash.
    #[command(group(
        ArgGroup::new("block_id")
            .required(true)
            .args(&["hash", "height"])
    ))]
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
        #[clap(long, short, conflicts_with = "hash", conflicts_with = "height")]
        era: Option<u64>,
        #[clap(long, conflicts_with = "height", conflicts_with = "era")]
        hash: Option<String>,
        #[clap(long, conflicts_with = "hash", conflicts_with = "era")]
        height: Option<u64>,
        #[clap(long, conflicts_with = "validator_key_file")]
        validator_key: Option<String>,
        #[clap(long, short, conflicts_with = "validator_key")]
        validator_key_file: Option<String>,
        #[clap(long, conflicts_with = "delegator_key_file")]
        delegator_key: Option<String>,
        #[clap(long, short, conflicts_with = "delegator_key")]
        delegator_key_file: Option<String>,
    },
}

impl Information {
    fn id(&self) -> InformationRequestTag {
        match self {
            Information::NodeStatus => InformationRequestTag::NodeStatus,
            Information::BlockHeader { .. } => InformationRequestTag::BlockHeader,
            Information::ChainspecRawBytes => InformationRequestTag::ChainspecRawBytes,
            Information::Uptime => InformationRequestTag::Uptime,
            Information::SignedBlock { .. } => InformationRequestTag::SignedBlock,
            Information::Transaction { .. } => InformationRequestTag::Transaction,
            Information::Peers => InformationRequestTag::Peers,
            Information::LastProgress => InformationRequestTag::LastProgress,
            Information::ReactorState => InformationRequestTag::ReactorState,
            Information::NetworkName => InformationRequestTag::NetworkName,
            Information::ConsensusValidatorChanges => {
                InformationRequestTag::ConsensusValidatorChanges
            }
            Information::BlockSynchronizerStatus => InformationRequestTag::BlockSynchronizerStatus,
            Information::AvailableBlockRange => InformationRequestTag::AvailableBlockRange,
            Information::NextUpgrade => InformationRequestTag::NextUpgrade,
            Information::ConsensusStatus => InformationRequestTag::ConsensusStatus,
            Information::LatestSwitchBlockHeader => InformationRequestTag::LatestSwitchBlockHeader,
            Information::Reward { .. } => InformationRequestTag::Reward,
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Information::BlockHeader { hash, height }
            | Information::SignedBlock { hash, height } => get_block_key(hash, height),
            Information::LastProgress
            | Information::BlockSynchronizerStatus
            | Information::AvailableBlockRange
            | Information::LatestSwitchBlockHeader
            | Information::Peers
            | Information::ConsensusStatus
            | Information::ConsensusValidatorChanges
            | Information::NetworkName
            | Information::ReactorState
            | Information::ChainspecRawBytes
            | Information::NodeStatus
            | Information::NextUpgrade
            | Information::Uptime => Default::default(),
            Information::Transaction {
                hash,
                with_finalized_approvals,
                legacy,
            } => {
                let digest = Digest::from_hex(hash).expect("failed to parse hash");
                let hash = if *legacy {
                    TransactionHash::Deploy(DeployHash::from(digest))
                } else {
                    TransactionHash::from_raw(digest.value())
                };
                let hash = hash.to_bytes().expect("should serialize");

                let approvals = with_finalized_approvals
                    .to_bytes()
                    .expect("should serialize");

                hash.into_iter().chain(approvals).collect()
            }
            Information::Reward {
                era,
                hash,
                height,
                validator_key,
                validator_key_file,
                delegator_key,
                delegator_key_file,
            } => {
                let era_identifier = match (era, hash, height) {
                    (Some(era), None, None) => Some(EraIdentifier::Era(EraId::new(*era))),
                    (None, Some(hash), None) => {
                        let digest = Digest::from_hex(hash).expect("failed to parse hash");
                        Some(EraIdentifier::Block(BlockIdentifier::Hash(BlockHash::new(
                            digest,
                        ))))
                    }
                    (None, None, Some(height)) => {
                        Some(EraIdentifier::Block(BlockIdentifier::Height(*height)))
                    }
                    (None, None, None) => None,
                    _ => unreachable!(
                        "era identifier should be either empty or one of era, hash, or height"
                    ),
                };

                let validator = match (validator_key, validator_key_file) {
                    (None, Some(key_file)) => Box::new(
                        PublicKey::from_file(key_file).expect("failed to read validator key file"),
                    ),
                    (Some(key), None) => {
                        Box::new(PublicKey::from_hex(key).expect("failed to parse validator"))
                    }
                    (None, None) => panic!("validator key is required"),
                    (Some(_), Some(_)) => {
                        panic!("only one of validator key or validator key file is allowed")
                    }
                };

                let delegator = match (delegator_key, delegator_key_file) {
                    (None, Some(key_file)) => Some(Box::new(
                        PublicKey::from_file(key_file).expect("failed to read delegator key file"),
                    )),
                    (Some(key), None) => Some(Box::new(
                        PublicKey::from_hex(key).expect("failed to parse delegator"),
                    )),
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        panic!("only one of delegator key or delegator key file is allowed")
                    }
                };

                let key = InformationRequest::Reward {
                    era_identifier,
                    validator,
                    delegator,
                };
                key.to_bytes().expect("should serialize")
            }
        }
    }
}

fn get_block_key(hash: &Option<String>, height: &Option<u64>) -> Vec<u8> {
    let block_id = match (hash, height) {
        (None, None) => None,
        (None, Some(height)) => Some(BlockIdentifier::Height(*height)),
        (Some(hash), None) => {
            let digest = casper_types::Digest::from_hex(hash).expect("failed to parse hash");
            Some(BlockIdentifier::Hash(BlockHash::new(digest)))
        }
        (Some(_), Some(_)) => {
            unreachable!("should not have both hash and height")
        }
    };
    block_id.to_bytes().expect("should serialize")
}

pub(super) async fn handle_information_request(
    node_address: &str,
    req: Information,
) -> Result<(), Error> {
    let id = req.id();
    let response = match id {
        InformationRequestTag::BlockHeader => todo!(),
        InformationRequestTag::SignedBlock => todo!(),
        InformationRequestTag::Transaction => todo!(),
        InformationRequestTag::Peers => todo!(),
        InformationRequestTag::Uptime => todo!(),
        InformationRequestTag::LastProgress => todo!(),
        InformationRequestTag::ReactorState => todo!(),
        InformationRequestTag::NetworkName => todo!(),
        InformationRequestTag::ConsensusValidatorChanges => todo!(),
        InformationRequestTag::BlockSynchronizerStatus => todo!(),
        InformationRequestTag::AvailableBlockRange => todo!(),
        InformationRequestTag::NextUpgrade => todo!(),
        InformationRequestTag::ConsensusStatus => todo!(),
        InformationRequestTag::ChainspecRawBytes => todo!(),
        InformationRequestTag::NodeStatus => todo!(),
        InformationRequestTag::LatestSwitchBlockHeader => latest_switch_block_header(node_address),
        InformationRequestTag::Reward => todo!(),
    }
    .await?;

    print_option(response);

    // let key = req.key();

    // let request = make_information_get_request(id, &key)?;
    // let response = send_request(request).await?;
    // handle_information_response(id, &response)?;

    Ok(())
}

fn handle_information_response(
    tag: InformationRequestTag,
    response: &BinaryResponseAndRequest,
) -> Result<(), Error> {
    match tag {
        InformationRequestTag::NodeStatus => {
            let res = parse_response::<NodeStatus>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::BlockHeader => {
            let res = parse_response::<BlockHeader>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::ChainspecRawBytes => {
            let res = parse_response::<ChainspecRawBytes>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::Uptime => {
            let res = parse_response::<Uptime>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::SignedBlock => {
            let res = parse_response::<SignedBlock>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::Transaction => {
            let res = parse_response::<TransactionWithExecutionInfo>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::Peers => {
            let res = parse_response::<Peers>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::LastProgress => {
            let res = parse_response::<LastProgress>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::ReactorState => {
            let res = parse_response::<ReactorStateName>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::NetworkName => {
            let res = parse_response::<NetworkName>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::ConsensusValidatorChanges => {
            let res = parse_response::<ConsensusValidatorChanges>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::BlockSynchronizerStatus => {
            let res = parse_response::<BlockSynchronizerStatus>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::AvailableBlockRange => {
            let res = parse_response::<AvailableBlockRange>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::NextUpgrade => {
            let res = parse_response::<NextUpgrade>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::ConsensusStatus => {
            let res = parse_response::<ConsensusStatus>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::LatestSwitchBlockHeader => {
            let res = parse_response::<BlockHeader>(response.response())?;
            print_option(res);
        }
        InformationRequestTag::Reward => {
            let res = parse_response::<RewardResponse>(response.response())?;
            print_option(res);
        }
    }
    Ok(())
}

fn parse_response<A: FromBytes + PayloadEntity>(
    response: &BinaryResponse,
) -> Result<Option<A>, Error> {
    match response.returned_data_type_tag() {
        Some(found) if found == u8::from(A::PAYLOAD_TYPE) => {
            // TODO: Verbose: print length of payload
            Ok(Some(bytesrepr::deserialize_from_slice(response.payload())?))
        }
        Some(other) => Err(Error::Response(format!(
            "unsupported response type: {other}"
        ))),
        _ => Ok(None),
    }
}

// TODO[RC]: Not needed here
fn make_information_get_request(
    tag: InformationRequestTag,
    key: &[u8],
) -> Result<BinaryRequest, Error> {
    let information_request = InformationRequest::try_from((tag, key))?;
    let get_request = information_request.try_into()?;
    Ok(BinaryRequest::Get(get_request))
}
