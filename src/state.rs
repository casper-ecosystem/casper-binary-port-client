use casper_binary_port::{
    BinaryRequest, BinaryResponseAndRequest, GetRequest, GlobalStateQueryResult,
    GlobalStateRequest, PayloadType,
};
use casper_types::{bytesrepr::FromBytes, Digest, GlobalStateIdentifier, Key, KeyTag, StoredValue};
use clap::Subcommand;

use crate::{communication::send_request, error::Error, utils::EMPTY_STR};

#[derive(Debug, Subcommand)]
pub(crate) enum State {
    /// Gets an item from the global state.
    Item {
        #[clap(long, conflicts_with = "block_hash", conflicts_with = "block_height")]
        state_root_hash: Option<String>,
        #[clap(
            long,
            conflicts_with = "block_height",
            conflicts_with = "state_root_hash"
        )]
        block_hash: Option<String>,
        #[clap(
            long,
            conflicts_with = "block_hash",
            conflicts_with = "state_root_hash"
        )]
        block_height: Option<u64>,
        #[clap(long, short)]
        base_key: String,
        #[clap(long, short)]
        path: Option<String>,
    },
    /// Get all items under the given key tag.
    #[command(
        after_help = "Please refer to `enum KeyTag` from the casper-node repository for valid key tags"
    )]
    AllItems {
        #[clap(long, conflicts_with = "block_hash", conflicts_with = "block_height")]
        state_root_hash: Option<String>,
        #[clap(
            long,
            conflicts_with = "block_height",
            conflicts_with = "state_root_hash"
        )]
        block_hash: Option<String>,
        #[clap(
            long,
            conflicts_with = "block_hash",
            conflicts_with = "state_root_hash"
        )]
        block_height: Option<u64>,
        #[clap(long, short)]
        key_tag: u8,
    },
}

impl TryFrom<State> for GlobalStateRequest {
    type Error = Error;

    fn try_from(value: State) -> Result<Self, Self::Error> {
        let global_state_request = match value {
            State::Item {
                state_root_hash,
                block_hash,
                block_height,
                base_key,
                path,
            } => {
                if path.is_some() {
                    // TODO: Support path
                    panic!("Path is not supported yet");
                }
                let state_identifier =
                    resolve_state_identifier(state_root_hash, block_hash, block_height)?;
                let base_key =
                    Key::from_formatted_str(&base_key).map_err(|err| Error::KeyFromStr(err))?;
                Ok(GlobalStateRequest::Item {
                    state_identifier,
                    base_key,
                    path: vec![],
                })
            }
            State::AllItems {
                state_root_hash,
                block_hash,
                block_height,
                key_tag,
            } => {
                let state_identifier =
                    resolve_state_identifier(state_root_hash, block_hash, block_height)?;

                let key_tag = match key_tag {
                    0 => KeyTag::Account,
                    1 => KeyTag::Hash,
                    2 => KeyTag::URef,
                    3 => KeyTag::Transfer,
                    4 => KeyTag::DeployInfo,
                    5 => KeyTag::EraInfo,
                    6 => KeyTag::Balance,
                    7 => KeyTag::Bid,
                    8 => KeyTag::Withdraw,
                    9 => KeyTag::Dictionary,
                    10 => KeyTag::SystemEntityRegistry,
                    11 => KeyTag::EraSummary,
                    12 => KeyTag::Unbond,
                    13 => KeyTag::ChainspecRegistry,
                    14 => KeyTag::ChecksumRegistry,
                    15 => KeyTag::BidAddr,
                    16 => KeyTag::Package,
                    17 => KeyTag::AddressableEntity,
                    18 => KeyTag::ByteCode,
                    19 => KeyTag::Message,
                    20 => KeyTag::NamedKey,
                    21 => KeyTag::BlockGlobal,
                    22 => KeyTag::BalanceHold,
                    23 => KeyTag::EntryPoint,
                    _ => return Err(Error::InvalidKeyTag(key_tag)),
                };

                Ok(GlobalStateRequest::AllItems {
                    state_identifier,
                    key_tag,
                })
            }
        };
        global_state_request
    }
}

fn resolve_state_identifier(
    state_root_hash: Option<String>,
    block_hash: Option<String>,
    block_height: Option<u64>,
) -> Result<Option<GlobalStateIdentifier>, <GlobalStateRequest as TryFrom<State>>::Error> {
    Ok(match (state_root_hash, block_hash, block_height) {
        (Some(state_root_hash), None, None) => {
            let digest = Digest::from_hex(state_root_hash)?;
            Some(GlobalStateIdentifier::StateRootHash(digest))
        },
        (None, Some(block_hash), None) => {
            let digest = Digest::from_hex(block_hash)?;
            Some(GlobalStateIdentifier::BlockHash(digest.into()))
        },
        (None, None, Some(block_height)) => Some(GlobalStateIdentifier::BlockHeight(block_height)),
        (None, None, None) => None,
        _ => unreachable!("global state must either be empty or be identified by exactly one of: state_root_hash, block_hash, block_height"),
    })
}

pub(super) async fn handle_state_request(req: State) -> Result<(), Error> {
    let request: GlobalStateRequest = req.try_into()?;
    let response = send_request(BinaryRequest::Get(GetRequest::State(Box::new(request)))).await?;
    handle_state_response(&response);

    Ok(())
}

fn handle_state_response(response: &BinaryResponseAndRequest) {
    let Some(tag) = response.response().returned_data_type_tag() else {
        println!("{EMPTY_STR}");
        return;
    };

    match tag {
        t if t == PayloadType::GlobalStateQueryResult as u8 => {
            let (result, remainder): (GlobalStateQueryResult, _) =
                FromBytes::from_bytes(&response.response().payload()).expect("should deserialize");
            assert!(remainder.is_empty(), "should have no remaining bytes");

            let (value, proof) = result.into_inner();
            println!("Value:");
            println!("{value:#?}");
            println!("Proof:");
            println!("{proof:#?}");
        }
        t if t == PayloadType::StoredValues as u8 => {
            let (result, remainder): (Vec<StoredValue>, _) =
                FromBytes::from_bytes(&response.response().payload()).expect("should deserialize");
            assert!(remainder.is_empty(), "should have no remaining bytes");
            println!("{} stored values:", result.len());
            for (index, value) in result.into_iter().enumerate() {
                println!("{}", index + 1);
                println!("{value:#?}");
            }
        }
        _ => panic!("unexpected payload type: {}", tag),
    }
}
