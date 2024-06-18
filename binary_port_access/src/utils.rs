use casper_binary_port::{
    BinaryRequest, EraIdentifier, InformationRequest, InformationRequestTag, RewardResponse,
};
use casper_types::{bytesrepr::ToBytes, PublicKey};

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
            delegator: Some(Box::new(delegator_key)),
        }
        .to_bytes()?
        .as_slice(),
    )?;
    let response = communication::send_request(node_address, request).await?;
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
