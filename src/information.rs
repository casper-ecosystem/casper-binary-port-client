use casper_binary_port::{
    BinaryRequest, BinaryResponse, BinaryResponseAndRequest, InformationRequest,
    InformationRequestTag, NodeStatus, PayloadEntity, TransactionWithExecutionInfo, Uptime,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    BlockHash, BlockHeader, BlockIdentifier, ChainspecRawBytes, DeployHash, SignedBlock,
    Transaction, TransactionHash,
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
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Information::BlockHeader { hash, height }
            | Information::SignedBlock { hash, height } => get_block_key(hash, height),
            Information::ChainspecRawBytes | Information::NodeStatus | Information::Uptime => {
                Default::default()
            }
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

                hash.into_iter().chain(approvals.into_iter()).collect()
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

    dbg!(&request);

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
            Ok(())
        }
        InformationRequestTag::BlockHeader => {
            let res = parse_response::<BlockHeader>(response.response())?;
            debug_print_option(res);
            Ok(())
        }
        InformationRequestTag::ChainspecRawBytes => {
            let res = parse_response::<ChainspecRawBytes>(response.response())?;
            debug_print_option(res);
            Ok(())
        }
        InformationRequestTag::Uptime => {
            let res = parse_response::<Uptime>(response.response())?;
            debug_print_option(res);
            Ok(())
        }
        InformationRequestTag::SignedBlock => {
            let res = parse_response::<SignedBlock>(response.response())?;
            debug_print_option(res);
            Ok(())
        }
        InformationRequestTag::Transaction => {
            let res = parse_response::<TransactionWithExecutionInfo>(response.response())?;
            debug_print_option(res);
            Ok(())
        }
        InformationRequestTag::Peers => todo!(),
        InformationRequestTag::LastProgress => todo!(),
        InformationRequestTag::ReactorState => todo!(),
        InformationRequestTag::NetworkName => todo!(),
        InformationRequestTag::ConsensusValidatorChanges => todo!(),
        InformationRequestTag::BlockSynchronizerStatus => todo!(),
        InformationRequestTag::AvailableBlockRange => todo!(),
        InformationRequestTag::NextUpgrade => todo!(),
        InformationRequestTag::ConsensusStatus => todo!(),
        InformationRequestTag::LatestSwitchBlockHeader => todo!(),
    }
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
    dbg!(1);
    let information_request = InformationRequest::try_from((tag, key))?;
    dbg!(2);
    let get_request = information_request.try_into()?;
    Ok(BinaryRequest::Get(get_request))
}
