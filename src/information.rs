use casper_binary_port::{
    BinaryRequest, BinaryResponse, BinaryResponseAndRequest, InformationRequest,
    InformationRequestTag, NodeStatus, PayloadEntity, Uptime,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    BlockHash, BlockHeader, BlockIdentifier, ChainspecRawBytes,
};

use crate::{
    args::Information, communication::send_request, error::RequestError, utils::debug_print_option,
};

impl Information {
    fn id(&self) -> InformationRequestTag {
        match self {
            Information::NodeStatus => InformationRequestTag::NodeStatus,
            Information::BlockHeader { .. } => InformationRequestTag::BlockHeader,
            Information::ChainspecRawBytes => InformationRequestTag::ChainspecRawBytes,
            Information::Uptime => InformationRequestTag::Uptime,
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Information::BlockHeader { hash, height } => {
                let block_id = match (hash, height) {
                    (None, None) => None,
                    (None, Some(height)) => Some(BlockIdentifier::Height(*height)),
                    (Some(hash), None) => {
                        let digest =
                            casper_types::Digest::from_hex(&hash).expect("failed to parse hash");
                        Some(BlockIdentifier::Hash(BlockHash::new(digest)))
                    }
                    (Some(_), Some(_)) => {
                        unreachable!("should not have both hash and height")
                    }
                };
                block_id.to_bytes().expect("should serialize")
            }
            Information::ChainspecRawBytes | Information::NodeStatus | Information::Uptime => {
                Default::default()
            }
        }
    }
}

pub(super) async fn handle_information_request(req: Information) -> Result<(), RequestError> {
    let id = req.id();
    let key = req.key();

    let request = make_info_get_request(id, &key)?;
    let response = send_request(request).await?;
    handle_information_response(id, &response)?;

    Ok(())
}

fn handle_information_response(
    tag: InformationRequestTag,
    response: &BinaryResponseAndRequest,
) -> Result<(), RequestError> {
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
        _ => unimplemented!(),
    }
}

fn parse_response<A: FromBytes + PayloadEntity>(
    response: &BinaryResponse,
) -> Result<Option<A>, RequestError> {
    match response.returned_data_type_tag() {
        Some(found) if found == u8::from(A::PAYLOAD_TYPE) => {
            println!("{}", response.payload().len());
            Ok(Some(bytesrepr::deserialize_from_slice(response.payload())?))
        }
        Some(other) => Err(RequestError::Response(format!(
            "unsupported response type: {other}"
        ))),
        _ => Ok(None),
    }
}

// TODO: _information_
fn make_info_get_request(
    tag: InformationRequestTag,
    key: &[u8],
) -> Result<BinaryRequest, RequestError> {
    let information_request = InformationRequest::try_from((tag, &key[..]))?;
    let get_request = information_request.try_into()?;
    Ok(BinaryRequest::Get(get_request))
}
