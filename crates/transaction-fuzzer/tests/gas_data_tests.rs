// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use proptest::arbitrary::*;
use proptest::prelude::*;
use proptest::proptest;
use sui_core::test_utils::{init_state, send_and_confirm_transaction};
use sui_protocol_config::ProtocolConfig;
use sui_types::base_types::dbg_addr;
use sui_types::crypto::get_key_pair;
use sui_types::crypto::AccountKeyPair;
use sui_types::messages::TransactionData;
use sui_types::messages::TransactionKind;
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::utils::to_sender_signed_transaction;
use tokio::runtime::Runtime;
use transaction_fuzzer::GasDataWithObjects;

/// Send transfer sui txn with provided random gas data and gas objects to a authority.
async fn test_with_random_gas_data(gas_data_test: GasDataWithObjects) {
    let mut gas_data = gas_data_test.gas_data;
    let objects = gas_data_test.objects;
    let (sender, sender_key): (_, AccountKeyPair) = get_key_pair();
    gas_data.owner = sender;

    let authority_state = init_state().await;
    // Insert the random gas objects into genesis.
    authority_state.insert_genesis_objects(&objects).await;
    let pt = {
        let mut builder = ProgrammableTransactionBuilder::new();
        let recipient = dbg_addr(2);
        builder.transfer_sui(recipient, None);
        builder.finish()
    };
    let kind = TransactionKind::ProgrammableTransaction(pt);
    let tx_data = TransactionData::new_with_gas_data(kind, sender, gas_data);
    let tx = to_sender_signed_transaction(tx_data, &sender_key);

    let result = send_and_confirm_transaction(&authority_state, None, tx).await;
    println!("result: {:?}", result);
}

proptest! {
    // Stops after 20 test cases.
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_gas_data(gas_data_test in any_with::<GasDataWithObjects>(ProtocolConfig::get_for_max_version().max_gas_payment_objects() as usize)) {
        let rt = Runtime::new().unwrap();

        let future = test_with_random_gas_data(gas_data_test);
        let _ = rt.block_on(future);

    }
}
