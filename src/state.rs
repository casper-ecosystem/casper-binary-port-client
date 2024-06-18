use casper_binary_port::{
    BinaryRequest, BinaryResponseAndRequest, GetRequest, GetTrieFullResult, GlobalStateQueryResult,
    GlobalStateRequest, PayloadType,
};
use casper_binary_port_access::global_state_item_by_state_root_hash;
use casper_types::{bytesrepr::FromBytes, Digest, GlobalStateIdentifier, Key, KeyTag, StoredValue};
use clap::Subcommand;

use crate::{
    error::Error,
    utils::{print_response, EMPTY_STR},
};

#[derive(Debug, Subcommand)]
pub(crate) enum DictionaryIdentifier {
    /// Lookup a dictionary item via an accounts named keys.
    AccountNamedKey {
        /// The account hash.
        #[clap(long, short)]
        account_hash: String,
        /// The named key under which the dictionary seed URef is stored.
        #[clap(long)]
        dictionary_name: String,
        /// The dictionary item key formatted as a string.
        #[clap(long)]
        dictionary_item_key: String,
    },
    /// Lookup a dictionary item via a contracts named keys.
    ContractNamedKey {
        /// The contract hash.
        #[clap(long, short)]
        contract_hash: String,
        /// The named key under which the dictionary seed URef is stored.
        #[clap(long)]
        dictionary_name: String,
        /// The dictionary item key formatted as a string.
        #[clap(long)]
        dictionary_item_key: String,
    },
    /// Lookup a dictionary item via an entities named keys.
    EntityNamedKey {
        /// The entity address.
        #[clap(long, short)]
        entity_addr: String,
        /// The named key under which the dictionary seed URef is stored.
        #[clap(long)]
        dictionary_name: String,
        /// The dictionary item key formatted as a string.
        #[clap(long)]
        dictionary_item_key: String,
    },
    /// Lookup a dictionary item via its seed URef.
    URef {
        /// The dictionary's seed URef.
        #[clap(long, short)]
        seed_uref: String,
        /// The dictionary item key formatted as a string.
        #[clap(long, short)]
        dictionary_item_key: String,
    },
    DictionaryItem {
        #[clap(long, short)]
        dictionary_addr: String,
    },
}

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
    /// Get a trie by its Digest.
    Trie {
        #[clap(long, short)]
        digest: String,
    },
    /// Get a dictionary item by its identifier.
    DictionaryItem {
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
        #[clap(subcommand)]
        dictionary_identifier: DictionaryIdentifier,
    },
}

fn resolve_state_identifier(
    state_root_hash: Option<String>,
    block_hash: Option<String>,
    block_height: Option<u64>,
) -> Result<Option<GlobalStateIdentifier>, Error> {
    match (state_root_hash, block_hash, block_height) {
        (Some(state_root_hash), None, None) => {
            let digest = Digest::from_hex(state_root_hash)?;
            Ok(Some(GlobalStateIdentifier::StateRootHash(digest)))
        }
        (None, Some(block_hash), None) => {
            let digest = Digest::from_hex(block_hash)?;
            Ok(Some(GlobalStateIdentifier::BlockHash(digest.into())))
        }
        (None, None, Some(block_height)) => {
            Ok(Some(GlobalStateIdentifier::BlockHeight(block_height)))
        }
        (None, None, None) => Ok(None),
        _ => Err(Error::InvalidStateIdentifier),
    }
}

pub(super) async fn handle_state_request(node_address: &str, req: State) -> Result<(), Error> {
    match req {
        State::Item {
            state_root_hash,
            block_hash,
            block_height,
            base_key,
            path,
        } => {
            if path.is_some() {
                unimplemented!("Path is not supported yet");
            }
            let state_identifier =
                resolve_state_identifier(state_root_hash, block_hash, block_height)?;
            let base_key = Key::from_formatted_str(&base_key).map_err(Error::KeyFromStr)?;

            match state_identifier {
                Some(state_identifier) => match state_identifier {
                    GlobalStateIdentifier::BlockHash(_) => todo!(),
                    GlobalStateIdentifier::BlockHeight(_) => todo!(),
                    GlobalStateIdentifier::StateRootHash(state_root_hash) => {
                        let global_state_query_result = global_state_item_by_state_root_hash(
                            node_address,
                            state_root_hash,
                            base_key,
                            vec![],
                        )
                        .await?;
                        print_response(global_state_query_result);
                    }
                },
                None => todo!(),
            }
        }
        State::AllItems {
            state_root_hash,
            block_hash,
            block_height,
            key_tag,
        } => todo!(),
        State::Trie { digest } => todo!(),
        State::DictionaryItem {
            state_root_hash,
            block_hash,
            block_height,
            dictionary_identifier,
        } => todo!(),
    }

    Ok(())

    /*
    match req {
        State::Item {
            state_root_hash,
            block_hash,
            block_height,
            base_key,
            path,
        } => {
            if path.is_some() {
                unimplemented!("Path is not supported yet");
            }
            let state_identifier =
                resolve_state_identifier(state_root_hash, block_hash, block_height)?;
            let base_key = Key::from_formatted_str(&base_key).map_err(Error::KeyFromStr)?;

            match state_identifier {
                Some(state_identifier) => match state_identifier {
                    GlobalStateIdentifier::BlockHash(_) => todo!(),
                    GlobalStateIdentifier::BlockHeight(_) => todo!(),
                    GlobalStateIdentifier::StateRootHash(state_root_hash) => {
                        global_state_item_by_state_root_hash(
                            node_address,
                            state_root_hash,
                            base_key,
                            path,
                        )
                        .await?
                    }
                },
                None => todo!(),
            }
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
        }
        State::Trie { digest } => {
            let digest = Digest::from_hex(digest)?;
        }
        State::DictionaryItem {
            state_root_hash: _,
            block_hash: _,
            block_height: _,
            dictionary_identifier: _,
        } => todo!(),
    }
    */
}

fn handle_state_response(response: &BinaryResponseAndRequest) {
    if !response.response().is_success() {
        let error_code = response.response().error_code();
        let error = casper_binary_port::ErrorCode::try_from(error_code)
            .expect("unknown binary port error code");
        println!("Error: {} (code={})", error, error_code);
        return;
    }

    let Some(tag) = response.response().returned_data_type_tag() else {
        println!("{EMPTY_STR}");
        return;
    };

    match tag {
        t if t == PayloadType::GlobalStateQueryResult as u8 => {
            let (result, remainder): (GlobalStateQueryResult, _) =
                FromBytes::from_bytes(response.response().payload()).expect("should deserialize");
            assert!(remainder.is_empty(), "should have no remaining bytes");

            let (value, proof) = result.into_inner();
            println!("Value:");
            println!("{value:#?}");
            println!("Proof:");
            println!("{proof:#?}");
        }
        t if t == PayloadType::StoredValues as u8 => {
            let (result, remainder): (Vec<StoredValue>, _) =
                FromBytes::from_bytes(response.response().payload()).expect("should deserialize");
            assert!(remainder.is_empty(), "should have no remaining bytes");
            println!("{} stored values:", result.len());
            for (index, value) in result.into_iter().enumerate() {
                println!("{}", index + 1);
                println!("{value:#?}");
            }
        }
        t if t == PayloadType::GetTrieFullResult as u8 => {
            let (result, remainder): (GetTrieFullResult, _) =
                FromBytes::from_bytes(response.response().payload()).expect("should deserialize");
            assert!(remainder.is_empty(), "should have no remaining bytes");

            let result = result.into_inner();
            match result {
                Some(bytes) => {
                    println!("Length (bytes):");
                    println!("{}", bytes.len());
                    println!("Bytes:");
                    println!("{}", hex::encode(bytes));
                }
                None => {
                    println!("{EMPTY_STR}");
                }
            }
        }
        _ => panic!("unexpected payload type: {}", tag),
    }
}
