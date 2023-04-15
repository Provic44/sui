// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use futures::executor::block_on;
use move_binary_format::CompiledModule;
use move_bytecode_utils::module_cache::GetModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::{ModuleId, StructTag};
use move_core_types::parser::parse_struct_tag;
use move_core_types::resolver::{ModuleResolver, ResourceResolver};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::Arc;
use sui_adapter::adapter;
use sui_adapter::execution_engine::execute_transaction_to_effects_impl;
use sui_adapter::execution_mode;
use sui_config::node::ExpensiveSafetyCheckConfig;
use sui_core::authority::TemporaryStore;
use sui_json_rpc_types::{
    EventFilter, SuiObjectData, SuiObjectDataOptions, SuiTransactionBlockResponseOptions,
};
use sui_json_rpc_types::{
    SuiObjectResponse, SuiTransactionBlockEffects, SuiTransactionBlockEffectsAPI,
};
use sui_protocol_config::ProtocolConfig;
use sui_sdk::error::Error as SuiRpcError;
use sui_sdk::{SuiClient, SuiClientBuilder};
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, VersionNumber};
use sui_types::committee::EpochId;
use sui_types::digests::TransactionDigest;
use sui_types::error::{SuiError, SuiObjectResponseError, SuiResult, UserInputError};
use sui_types::gas::SuiGasStatus;
use sui_types::messages::{InputObjectKind, InputObjects, TransactionEffectsAPI};
use sui_types::messages::{SenderSignedData, TransactionDataAPI};
use sui_types::object::{Data, Object, Owner};
use sui_types::storage::get_module_by_id;
use sui_types::storage::{BackingPackageStore, ChildObjectResolver, ObjectStore, ParentSync};
use thiserror::Error;

pub struct LocalExec {
    client: SuiClient,
    testnet: bool,
    curr_tx: Option<TransactionDigest>,
    store: BTreeMap<ObjectID, Object>,
    package_cache: RefCell<BTreeMap<ObjectID, Object>>,
    object_version_cache: RefCell<BTreeMap<(ObjectID, SequenceNumber), Object>>,
}

/// Custom error type for Sui.
#[derive(Debug, Serialize, Deserialize, Error, Hash)]
pub enum LocalExecError {
    #[error("SuiError: {:?}", err)]
    SuiError { err: SuiError },

    #[error("SuiRpcError: {:?}", err)]
    SuiRpcError { err: String },

    #[error("SuiObjectResponseError: {:?}", err)]
    SuiObjectResponseError { err: SuiObjectResponseError },

    #[error("UserInputError: {:?}", err)]
    UserInputError { err: UserInputError },

    #[error("GeneralError: {:?}", err)]
    GeneralError { err: String },
}

impl From<LocalExecError> for SuiError {
    fn from(err: LocalExecError) -> Self {
        SuiError::Unknown(format!("{:?}", err))
    }
}

impl From<SuiError> for LocalExecError {
    fn from(err: SuiError) -> Self {
        LocalExecError::SuiError { err }
    }
}
impl From<SuiRpcError> for LocalExecError {
    fn from(err: SuiRpcError) -> Self {
        LocalExecError::SuiRpcError {
            err: format!("{:?}", err),
        }
    }
}

impl From<UserInputError> for LocalExecError {
    fn from(err: UserInputError) -> Self {
        LocalExecError::UserInputError { err }
    }
}

impl From<anyhow::Error> for LocalExecError {
    fn from(err: anyhow::Error) -> Self {
        LocalExecError::GeneralError {
            err: format!("{:?}", err),
        }
    }
}

fn obj_from_sui_obj_response(o: &SuiObjectResponse) -> Result<Object, LocalExecError> {
    let o: Result<SuiObjectData, anyhow::Error> = Ok(o
        .object()
        .map_err(|q| LocalExecError::SuiObjectResponseError { err: q })?
        .clone());

    obj_from_sui_obj_data(&o.map_err(|q| LocalExecError::GeneralError { err: q.to_string() })?)
}

fn obj_from_sui_obj_data(o: &SuiObjectData) -> Result<Object, LocalExecError> {
    match TryInto::<Object>::try_into(o.clone()) {
        Ok(obj) => Ok(obj),
        Err(e) => Err(e.into()),
    }
}

impl LocalExec {
    pub async fn new_from_fn_url(http_url: &str) -> Self {
        Self::new(
            SuiClientBuilder::default().build(http_url).await.unwrap(),
            true, // Temporary hack due to epoch speed run bug. TODO: remove
        )
    }

    pub fn new(client: SuiClient, testnet: bool) -> Self {
        Self {
            client,
            testnet,
            curr_tx: None,
            store: BTreeMap::new(),
            package_cache: BTreeMap::new().into(),
            object_version_cache: BTreeMap::new().into(),
        }
    }

    pub fn to_temporary_store(
        &mut self,
        tx_digest: &TransactionDigest,
        input_objects: InputObjects,
        protocol_config: &ProtocolConfig,
    ) -> TemporaryStore<&mut LocalExec> {
        TemporaryStore::new(self, input_objects, *tx_digest, protocol_config)
    }

    pub fn download_object(
        &self,
        object_id: &ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, LocalExecError> {
        if self
            .object_version_cache
            .borrow()
            .contains_key(&(*object_id, version))
        {
            return Ok(self
                .object_version_cache
                .borrow()
                .get(&(*object_id, version))
                .ok_or(LocalExecError::GeneralError {
                    err: format!("Object not found in cache {} {}", object_id, version),
                })?
                .clone());
        }

        let options = SuiObjectDataOptions::bcs_lossless();
        let object = block_on({
            self.client
                .read_api()
                .try_get_parsed_past_object(*object_id, version, options)
        })
        .map_err(|q| LocalExecError::SuiRpcError { err: q.to_string() })?;

        let o = match object {
            sui_json_rpc_types::SuiPastObjectResponse::VersionFound(o) => obj_from_sui_obj_data(&o),

            e => Err(LocalExecError::GeneralError {
                err: format!("Obj deleted {:?} ", e),
            }),
        }?;
        let o_ref = o.compute_object_reference();
        self.object_version_cache
            .borrow_mut()
            .insert((o_ref.0, o_ref.1), o.clone());
        Ok(o)
    }

    pub fn download_latest_object(&self, object_id: &ObjectID) -> Result<Object, LocalExecError> {
        block_on(self.download_latest_object_impl(object_id))
    }

    pub async fn download_latest_object_impl(
        &self,
        object_id: &ObjectID,
    ) -> Result<Object, LocalExecError> {
        let options = SuiObjectDataOptions::bcs_lossless();
        let object = self
            .client
            .read_api()
            .get_object_with_options(*object_id, options)
            .await
            .map_err(|q| LocalExecError::SuiRpcError { err: q.to_string() })?;

        obj_from_sui_obj_response(&object)
    }

    pub fn execute(
        &mut self,
        tx_digest: &TransactionDigest,
        expensive_safety_check_config: ExpensiveSafetyCheckConfig,
    ) -> Result<Vec<TransactionDigest>, LocalExecError> {
        self.curr_tx = Some(*tx_digest);
        let tx_fetch_opts = SuiTransactionBlockResponseOptions::full_content();

        let tx_info = block_on({
            self.client
                .read_api()
                .get_transaction_with_options(*tx_digest, tx_fetch_opts)
        })
        .map_err(LocalExecError::from)?;
        let sender = match tx_info.clone().transaction.unwrap().data {
            sui_json_rpc_types::SuiTransactionBlockData::V1(tx) => tx.sender,
        };
        if sender == SuiAddress::ZERO {
            println!("Genesis TX {tx_digest} from sender {sender} exiting");
            // Genesis.
            return Ok(vec![]);
        }

        let raw_tx_bytes = tx_info.clone().raw_transaction;
        let orig_tx: SenderSignedData = bcs::from_bytes(&raw_tx_bytes).unwrap();
        let input_objs = orig_tx
            .transaction_data()
            .input_objects()
            .map_err(|e| LocalExecError::UserInputError { err: e })?;
        let tx_kind_orig = orig_tx.transaction_data().kind();

        let SuiTransactionBlockEffects::V1(effects) = tx_info.clone().effects.unwrap();

        // Download the objects at the version right before the execution of this TX
        let mut pre_exec_objects: Vec<_> = effects
            .modified_at_versions()
            .iter()
            .map(|(object_id, sequence_number)| self.download_object(object_id, *sequence_number))
            .collect::<Result<Vec<_>, _>>()?;

        let mut wrapped_objects: Vec<_> = effects
            .wrapped()
            .iter()
            .map(|s| self.download_object(&s.object_id, s.version))
            .collect::<Result<Vec<_>, _>>()?;
        let mut unwrapped_then_deleted: Vec<_> = effects
            .unwrapped_then_deleted()
            .iter()
            .map(|s| self.download_object(&s.object_id, s.version))
            .collect::<Result<Vec<_>, _>>()?;

        pre_exec_objects.append(&mut wrapped_objects);
        pre_exec_objects.append(&mut unwrapped_then_deleted);

        let mutated_at_versions: Vec<(ObjectID, SequenceNumber)> =
            effects.modified_at_versions().clone();

        let shared_objs: Vec<_> = effects
            .shared_objects
            .iter()
            .map(|obj_ref| self.download_object(&(obj_ref.object_id), obj_ref.version))
            .collect::<Result<Vec<_>, _>>()?;

        pre_exec_objects.iter().for_each(|obj| {
            self.store.insert(obj.id(), obj.clone());
        });
        shared_objs.iter().for_each(|obj| {
            self.store.insert(obj.id(), obj.clone());
        });

        let gas_data = match tx_info.clone().transaction.unwrap().data {
            sui_json_rpc_types::SuiTransactionBlockData::V1(tx) => tx.gas_data,
        };
        let gas_object_refs: Vec<_> = gas_data
            .payment
            .iter()
            .map(|obj_ref| obj_ref.to_object_ref())
            .collect();

        let native_functions = sui_framework::natives::all_natives(/* disable silent */ false);

        let epoch_id = effects.executed_epoch;

        let protocol_config = block_on(self.get_protocol_config(epoch_id))?;

        let move_vm = Arc::new(
            adapter::new_move_vm(
                native_functions.clone(),
                &protocol_config,
                expensive_safety_check_config.enable_move_vm_paranoid_checks(),
            )
            .expect("We defined natives to not fail here"),
        );

        let timestamp_ms = tx_info.timestamp_ms.unwrap();

        let in_obj: Vec<_> = input_objs
            .iter()
            .map(|kind| {
                match kind {
                    InputObjectKind::MovePackage(i) => self.download_latest_object(i),
                    InputObjectKind::ImmOrOwnedMoveObject(o_ref) => {
                        self.download_object(&o_ref.0, o_ref.1)
                    }
                    InputObjectKind::SharedMoveObject {
                        id,
                        initial_shared_version: _,
                        mutable: _,
                    } => self
                        .store
                        .get(id)
                        .cloned()
                        .ok_or(LocalExecError::GeneralError {
                            err: format!(
                                "Object not found in cache {}. Should've been downloaded",
                                id
                            ),
                        }), // we already downloaded
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        in_obj.iter().for_each(|obj| {
            self.store.insert(obj.id(), obj.clone());
        });

        // Get the dynamic fields loaded
        let loaded_df_child_objs = block_on({
            self.client
                .read_api()
                .get_dynamic_fields_loaded_objects(*tx_digest)
        })?;
        loaded_df_child_objs
            .loaded_child_objects
            .iter()
            .for_each(|obj| {
                let obj = self
                    .download_object(&obj.object_id(), obj.sequence_number())
                    .unwrap_or_else(|_| {
                        panic!(
                            "Must be able to get version object {} at version {}",
                            obj.object_id(),
                            obj.sequence_number()
                        )
                    });
                self.store.insert(obj.id(), obj);
            });

        let temporary_store = self.to_temporary_store(
            tx_digest,
            InputObjects::new(input_objs.into_iter().zip(in_obj).collect()),
            &protocol_config,
        );

        let shared_obj_refs: Vec<_> = shared_objs
            .iter()
            .map(|obj| obj.compute_object_reference())
            .collect();

        let gas_used_actual = effects.clone().gas_used;
        let tx_deps: Vec<_> = effects.clone().dependencies.into_iter().collect();
        let transaction_dependencies: BTreeSet<_> = tx_deps.clone().into_iter().collect();

        // All prep done

        let gas_status =
            SuiGasStatus::new_with_budget(gas_data.budget, gas_data.price, &protocol_config);
        let res = execute_transaction_to_effects_impl::<execution_mode::Normal, _>(
            shared_obj_refs,
            temporary_store,
            tx_kind_orig.clone(),
            sender,
            &gas_object_refs,
            *tx_digest,
            transaction_dependencies,
            &move_vm,
            gas_status,
            &epoch_id,
            timestamp_ms,
            &protocol_config,
            true,
        );

        let new_effects: SuiTransactionBlockEffects = res.1.clone().try_into().unwrap();
        let new_effects = match new_effects {
            SuiTransactionBlockEffects::V1(e) => e,
        };

        if effects != new_effects {
            println!("EFFECTS DIFFER");
            println!("OLD {:?}", effects);
            println!("NEW {:?}", new_effects);
            panic!("Effects differ");
        }
        assert!(
            gas_used_actual == res.1.gas_cost_summary().clone(),
            "Actual gas used differs from local exec gas used"
        );

        println!("RES {:?}", res);

        Ok(tx_deps)
    }

    pub fn get_or_download_object(&self, obj_id: &ObjectID) -> Result<Object, LocalExecError> {
        if let Some(obj) = self.package_cache.borrow().get(obj_id) {
            return Ok(obj.clone());
        };
        let o = match self.store.get(obj_id) {
            Some(obj) => obj.clone(),
            None => self.download_latest_object(obj_id)?,
        };

        if o.is_package() {
            self.package_cache.borrow_mut().insert(*obj_id, o.clone());
        }
        let o_ref = o.compute_object_reference();
        self.object_version_cache
            .borrow_mut()
            .insert((o_ref.0, o_ref.1), o.clone());
        Ok(o)
    }

    pub async fn get_nearest_less_child_version(
        &self,
        parent: (ObjectID, SequenceNumber),
        child: ObjectID,
    ) -> Result<SequenceNumber, LocalExecError> {
        let mut child_id = child;
        let mut child_version = self
            .download_latest_object_impl(&child)
            .await?
            .compute_object_reference()
            .1;
        // Get the latest child object

        while child_version > parent.1 {
            let child_obj = self.download_latest_object_impl(&child).await?;
            // This is the tx which last created or mutated this obj
            let prev_tx = child_obj.previous_transaction;

            if prev_tx == TransactionDigest::genesis() || prev_tx == self.curr_tx.unwrap() {
                break;
            }

            // Check the version the object was mutated at
            let tx_fetch_opts = SuiTransactionBlockResponseOptions::full_content();

            let tx_info = self
                .client
                .read_api()
                .get_transaction_with_options(prev_tx, tx_fetch_opts)
                .await
                .map_err(LocalExecError::from)?;
            let SuiTransactionBlockEffects::V1(effects) = tx_info.clone().effects.unwrap();
            let mutated_at_versions: Vec<(ObjectID, SequenceNumber)> =
                effects.modified_at_versions().clone();

            let v = mutated_at_versions
                .iter()
                .find(|(id, _)| *id == child_id)
                .unwrap_or_else(|| panic!("Failed to find mutated at for {}", child));

            child_version = v.1;
        }

        Ok(child_version)
    }

    pub async fn get_protocol_config(
        &self,
        epoch_id: EpochId,
    ) -> Result<ProtocolConfig, LocalExecError> {
        // Known issue where epoch id less than 743 is not in testnet FNs
        if epoch_id < 743 && self.testnet {
            return Ok(ProtocolConfig::get_for_version(1.into()));
        }

        let struct_tag_str = "0x3::sui_system_state_inner::SystemEpochInfoEvent".to_string();
        let struct_tag = parse_struct_tag(&struct_tag_str).unwrap();

        // Should probably limit this but okay for now
        let resp = self
            .client
            .event_api()
            .query_events(EventFilter::MoveEventType(struct_tag), None, None, true)
            .await
            .map_err(|w| LocalExecError::GeneralError {
                err: format!("Error querying system events: {:?}", w),
            })?;

        for r in resp.data {
            match r.parsed_json {
                serde_json::Value::Object(w) => {
                    let ep_id = u64::from_str(&w["epoch"].to_string().replace('\"', "")).unwrap();
                    let prot_ver =
                        u64::from_str(&w["protocol_version"].to_string().replace('\"', ""))
                            .unwrap();
                    if ep_id == epoch_id {
                        return Ok(ProtocolConfig::get_for_version(prot_ver.into()));
                    }
                }

                _ => panic!("Unexpected event info"),
            };
        }
        Err(LocalExecError::GeneralError {
            err: format!("No protocol version found for epoch {:?}", epoch_id),
        })
    }
}

impl BackingPackageStore for LocalExec {
    fn get_package_object(&self, package_id: &ObjectID) -> SuiResult<Option<Object>> {
        self.get_or_download_object(package_id)
            .map(Some)
            .map_err(|e| e.into())
    }
}

impl ChildObjectResolver for LocalExec {
    fn read_child_object(&self, parent: &ObjectID, child: &ObjectID) -> SuiResult<Option<Object>> {
        let child_object = match self.get_object(child)? {
            None => return Ok(None),
            Some(o) => o,
        };

        let parent = *parent;
        if child_object.owner != Owner::ObjectOwner(parent.into()) {
            return Err(SuiError::InvalidChildObjectAccess {
                object: *child,
                given_parent: parent,
                actual_owner: child_object.owner,
            });
        }
        Ok(Some(child_object))
    }

    // fn read_child_object(&self, parent: &ObjectID, child: &ObjectID) -> SuiResult<Option<Object>> {
    //     println!("read_child_object: {} {}", parent, child);

    //     if self.store.get(parent).is_none() {
    //         println!("Could not find parent: {} {}", parent, child);
    //         return Ok(None);
    //     };

    //     let parent_obj = self.store.get(parent).unwrap();
    //     let parent_ref = parent_obj.compute_object_reference();

    //     println!("parent ref: {:?}", parent_ref);

    //     let child_version = block_on({
    //         self.get_nearest_less_child_version((parent_ref.0, parent_ref.1), *child)
    //     })?;

    //     if child_version > parent_ref.1 {
    //         // This means the child was created later
    //         return Ok(None);
    //     }

    //     let child_object = match self.download_object(child, parent_ref.1) {
    //         Err(_) => return Ok(None),
    //         Ok(obj) => obj,
    //     };
    //     let parent = *parent;
    //     if child_object.owner != Owner::ObjectOwner(parent.into()) {
    //         return Err(SuiError::InvalidChildObjectAccess {
    //             object: *child,
    //             given_parent: parent,
    //             actual_owner: child_object.owner,
    //         });
    //     }
    //     Ok(Some(child_object))
    // }
}

impl ParentSync for LocalExec {
    fn get_latest_parent_entry_ref(&self, object_id: ObjectID) -> SuiResult<Option<ObjectRef>> {
        // Need to improve this

        match self.get_or_download_object(&object_id) {
            Ok(obj) => Ok(Some(obj.compute_object_reference())),
            Err(e) => Err(e.into()),
        }
    }
}

impl ResourceResolver for LocalExec {
    type Error = LocalExecError;

    fn get_resource(
        &self,
        address: &AccountAddress,
        typ: &StructTag,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let object: Object = self.get_or_download_object(&ObjectID::from(*address))?;

        match &object.data {
            Data::Move(m) => {
                assert!(
                    m.is_type(typ),
                    "Invariant violation: ill-typed object in storage \
                    or bad object request from caller"
                );
                Ok(Some(m.contents().to_vec()))
            }
            other => unimplemented!(
                "Bad object lookup: expected Move object, but got {:?}",
                other
            ),
        }
    }
}

impl ModuleResolver for LocalExec {
    type Error = LocalExecError;

    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .get_package(&ObjectID::from(*module_id.address()))
            .map_err(LocalExecError::from)?
            .and_then(|package| {
                package
                    .serialized_module_map()
                    .get(module_id.name().as_str())
                    .cloned()
            }))
    }
}

impl ModuleResolver for &mut LocalExec {
    type Error = LocalExecError;

    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        (**self).get_module(module_id)
    }
}

impl ObjectStore for LocalExec {
    fn get_object(&self, object_id: &ObjectID) -> Result<Option<Object>, SuiError> {
        Ok(self.get_or_download_object(object_id).ok())
    }

    fn get_object_by_key(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> Result<Option<Object>, SuiError> {
        Ok(self.get_or_download_object(object_id).ok().and_then(|obj| {
            if obj.version() == version {
                Some(obj)
            } else {
                None
            }
        }))
    }
}

impl ObjectStore for &mut LocalExec {
    fn get_object(&self, object_id: &ObjectID) -> Result<Option<Object>, SuiError> {
        (**self).get_object(object_id)
    }

    fn get_object_by_key(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> Result<Option<Object>, SuiError> {
        (**self).get_object_by_key(object_id, version)
    }
}

impl GetModule for LocalExec {
    type Error = LocalExecError;
    type Item = CompiledModule;

    fn get_module_by_id(&self, id: &ModuleId) -> anyhow::Result<Option<Self::Item>, Self::Error> {
        get_module_by_id(self, id).map_err(|e| e.into())
    }
}
