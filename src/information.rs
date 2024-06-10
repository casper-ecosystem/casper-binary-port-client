use casper_binary_port::{
    BinaryRequest, BinaryResponse, BinaryResponseAndRequest, ConsensusValidatorChanges,
    InformationRequest, InformationRequestTag, LastProgress, NetworkName, NodeStatus,
    PayloadEntity, ReactorStateName, TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    BlockHash, BlockHeader, BlockIdentifier, BlockSynchronizerStatus, ChainspecRawBytes,
    DeployHash, Peers, SignedBlock, TransactionHash,
};

use crate::{
    args::Information, communication::send_request, error::Error, utils::debug_print_option,
};

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
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Information::BlockHeader { hash, height }
            | Information::SignedBlock { hash, height } => get_block_key(hash, height),
            Information::LastProgress
            | Information::BlockSynchronizerStatus
            | Information::Peers
            | Information::ConsensusValidatorChanges
            | Information::NetworkName
            | Information::ReactorState
            | Information::ChainspecRawBytes
            | Information::NodeStatus
            | Information::Uptime => Default::default(),
            Information::Transaction {
                hash,
                with_finalized_approvals,
                legacy,
            } => {
                let digest = casper_types::Digest::from_hex(hash).expect("failed to parse hash");
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

pub(super) async fn handle_information_request(req: Information) -> Result<(), Error> {
    let id = req.id();
    let key = req.key();

    let request = make_information_get_request(id, &key)?;
    let response = send_request(request).await?;
    handle_information_response(id, &response)?;

    Ok(())
}

fn handle_information_response(
    tag: InformationRequestTag,
    response: &BinaryResponseAndRequest,
) -> Result<(), Error> {
    match tag {
        // TODO: Macro?
        InformationRequestTag::NodeStatus => {
            let res = parse_response::<NodeStatus>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::BlockHeader => {
            let res = parse_response::<BlockHeader>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::ChainspecRawBytes => {
            let res = parse_response::<ChainspecRawBytes>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::Uptime => {
            let res = parse_response::<Uptime>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::SignedBlock => {
            let res = parse_response::<SignedBlock>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::Transaction => {
            let res = parse_response::<TransactionWithExecutionInfo>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::Peers => {
            let res = parse_response::<Peers>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::LastProgress => {
            let res = parse_response::<LastProgress>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::ReactorState => {
            let res = parse_response::<ReactorStateName>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::NetworkName => {
            let res = parse_response::<NetworkName>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::ConsensusValidatorChanges => {
            let res = parse_response::<ConsensusValidatorChanges>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::BlockSynchronizerStatus => {
            let res = parse_response::<BlockSynchronizerStatus>(response.response())?;
            debug_print_option(res);
        }
        InformationRequestTag::AvailableBlockRange => todo!(),
        InformationRequestTag::NextUpgrade => todo!(),
        InformationRequestTag::ConsensusStatus => todo!(),
        InformationRequestTag::LatestSwitchBlockHeader => todo!(),
        InformationRequestTag::Reward => todo!(),
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

fn make_information_get_request(
    tag: InformationRequestTag,
    key: &[u8],
) -> Result<BinaryRequest, Error> {
    let information_request = InformationRequest::try_from((tag, key))?;
    let get_request = information_request.try_into()?;
    Ok(BinaryRequest::Get(get_request))
}
