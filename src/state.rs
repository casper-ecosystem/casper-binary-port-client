use casper_binary_port_access::{
    global_state_item, global_state_item_by_block_hash, global_state_item_by_block_height,
    global_state_item_by_state_root_hash,
};
use casper_types::{Digest, GlobalStateIdentifier, Key};
use clap::Subcommand;

use crate::{error::Error, json_print::JsonPrintable};

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

pub(super) async fn handle_state_request(
    node_address: &str,
    req: State,
) -> Result<Box<dyn JsonPrintable>, Error> {
    Ok(match req {
        State::Item {
            state_root_hash,
            block_hash,
            block_height,
            base_key,
            path,
        } => {
            if path.is_some() {
                unimplemented!("Path in 'item' request is not supported yet");
            }
            let state_identifier =
                resolve_state_identifier(state_root_hash, block_hash, block_height)?;
            let base_key = Key::from_formatted_str(&base_key).map_err(Error::KeyFromStr)?;

            match state_identifier {
                Some(state_identifier) => match state_identifier {
                    GlobalStateIdentifier::BlockHash(block_hash) => Box::new(
                        global_state_item_by_block_hash(node_address, block_hash, base_key, vec![])
                            .await?,
                    ),
                    GlobalStateIdentifier::BlockHeight(block_height) => Box::new(
                        global_state_item_by_block_height(
                            node_address,
                            block_height,
                            base_key,
                            vec![],
                        )
                        .await?,
                    ),
                    GlobalStateIdentifier::StateRootHash(state_root_hash) => Box::new(
                        global_state_item_by_state_root_hash(
                            node_address,
                            state_root_hash,
                            base_key,
                            vec![],
                        )
                        .await?,
                    ),
                },
                None => Box::new(global_state_item(node_address, base_key, vec![]).await?),
            }
        }
        State::AllItems {
            state_root_hash: _,
            block_hash: _,
            block_height: _,
            key_tag: _,
        } => unimplemented!("State::AllItems is not supported yet"),
        State::Trie { digest: _ } => unimplemented!("State::Trie is not supported yet"),
        State::DictionaryItem {
            state_root_hash: _,
            block_hash: _,
            block_height: _,
            dictionary_identifier: _,
        } => unimplemented!("State::DictionaryItem is not supported yet"),
    })
}
