use casper_binary_port::{
    BinaryRequest, BinaryResponse, BinaryResponseAndRequest, EraIdentifier, GetRequest,
    GlobalStateEntityQualifier, GlobalStateQueryResult, GlobalStateRequest, InformationRequest,
    InformationRequestTag, RecordId, RewardResponse,
};
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    system::auction::DelegatorKind,
    GlobalStateIdentifier, Key, PublicKey,
};

use crate::{
    communication::{self, parse_response},
    Error,
};

pub(crate) fn make_information_get_request(
    tag: InformationRequestTag,
    key: &[u8],
) -> Result<BinaryRequest, Error> {
    let information_request = InformationRequest::try_from((tag, key))?;
    let get_request = information_request.try_into()?;
    Ok(BinaryRequest::Get(get_request))
}

pub(crate) fn make_record_request(record_id: RecordId, key: &[u8]) -> BinaryRequest {
    BinaryRequest::Get(GetRequest::Record {
        key: key.to_vec(),
        record_type_tag: record_id as u16,
    })
}

pub(crate) async fn delegator_reward_by_era_identifier(
    node_address: &str,
    validator_key: PublicKey,
    delegator_key: PublicKey,
    era_identifier: EraIdentifier,
) -> Result<Option<RewardResponse>, Error> {
    let request = make_information_get_request(
        InformationRequestTag::Reward,
        InformationRequest::Reward {
            era_identifier: Some(era_identifier),
            validator: Box::new(validator_key),
            delegator: Some(Box::new(DelegatorKind::PublicKey(delegator_key))),
        }
        .to_bytes()?
        .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<RewardResponse>(response.response())
}

pub(crate) async fn validator_reward_by_era_identifier(
    node_address: &str,
    validator_key: PublicKey,
    era_identifier: EraIdentifier,
) -> Result<Option<RewardResponse>, Error> {
    let request = make_information_get_request(
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
    parse_response::<RewardResponse>(response.response())
}

pub(crate) async fn global_state_item_by_state_identifier(
    node_address: &str,
    global_state_identifier: Option<GlobalStateIdentifier>,
    key: Key,
    path: Vec<String>,
) -> Result<Option<GlobalStateQueryResult>, Error> {
    let qualifier = GlobalStateEntityQualifier::Item {
        base_key: key,
        path,
    };
    let global_state_request = GlobalStateRequest::new(global_state_identifier, qualifier);
    let request = BinaryRequest::Get(GetRequest::State(Box::new(global_state_request)));
    let response = communication::send_request(node_address, request).await?;
    check_error_code(&response)?;
    parse_response::<GlobalStateQueryResult>(response.response())
}

pub(crate) async fn send_raw_bytes(
    node_address: &str,
    raw: Vec<u8>,
) -> Result<BinaryResponse, Error> {
    let response = communication::send_raw(node_address, raw).await?;
    check_error_code(&response)?;
    let response_bytes = response.response().to_bytes().map_err(Error::Bytesrepr)?;
    let (response, remainder) = FromBytes::from_bytes(&response_bytes).map_err(Error::Bytesrepr)?;
    if !remainder.is_empty() {
        return Err(Error::Bytesrepr(bytesrepr::Error::LeftOverBytes));
    }
    Ok(response)
}

pub(crate) fn check_error_code(response: &BinaryResponseAndRequest) -> Result<(), Error> {
    if response.response().is_success() {
        Ok(())
    } else {
        let error_code = response.error_code();
        Err(Error::Response(format!(
            "({}) {}",
            error_code,
            casper_binary_port::ErrorCode::try_from(error_code)
                .map_or("Unknown error code".to_string(), |code| code.to_string())
        )))
    }
}
