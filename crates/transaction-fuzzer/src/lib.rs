// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use proptest::collection::vec;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::digests::TransactionDigest;
use sui_types::object::{MoveObject, Object, Owner, OBJECT_START_VERSION};
use sui_types::{gas_coin::TOTAL_SUPPLY_MIST, messages::GasData};

use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

fn new_gas_coin_with_balance_and_owner(balance: u64, owner: Owner) -> Object {
    Object::new_move(
        MoveObject::new_gas_coin(OBJECT_START_VERSION, ObjectID::random(), balance),
        owner,
        TransactionDigest::genesis(),
    )
}

/// Given a sender address and a list of gas coin owners, generate random gas data and gas coins
/// with the given owners.
fn generate_random_gas_data(
    seed: [u8; 32],
    sender: SuiAddress,
    gas_coin_owners: Vec<Owner>, // arbitrarily generated owners, can be shared or immutable or obj-owned too
) -> GasDataWithObjects {
    let mut rng = StdRng::from_seed(seed);
    let mut gas_objects = vec![];
    let mut object_refs = vec![];

    let max_gas_balance = TOTAL_SUPPLY_MIST;

    let total_gas_balance = rng.gen_range(0..=max_gas_balance);
    let mut remaining_gas_balance = total_gas_balance;
    let num_gas_objects = gas_coin_owners.len();
    for owner in gas_coin_owners.iter().take(num_gas_objects - 1) {
        let gas_balance = rng.gen_range(0..=remaining_gas_balance);
        let gas_object = new_gas_coin_with_balance_and_owner(gas_balance, *owner);
        remaining_gas_balance -= gas_balance;
        object_refs.push(gas_object.compute_object_reference());
        gas_objects.push(gas_object);
    }
    // Put the remaining balance in the last gas object.
    gas_objects.push(new_gas_coin_with_balance_and_owner(
        remaining_gas_balance,
        gas_coin_owners[num_gas_objects - 1],
    ));

    assert_eq!(gas_objects.len(), num_gas_objects);
    assert_eq!(
        gas_objects
            .iter()
            .map(|o| o.data.try_as_move().unwrap().get_coin_value_unsafe())
            .sum::<u64>(),
        total_gas_balance
    );

    GasDataWithObjects {
        gas_data: GasData {
            payment: object_refs,
            owner: sender,
            price: rng.gen_range(0..=u64::MAX),
            budget: rng.gen_range(0..=u64::MAX),
        },
        objects: gas_objects,
    }
}

/// Need to have a wrapper struct here so we can implement Arbitrary for it.
#[derive(Debug)]
pub struct GasDataWithObjects {
    pub gas_data: GasData,
    pub objects: Vec<Object>,
}

impl proptest::arbitrary::Arbitrary for GasDataWithObjects {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_num_gas_objects: Self::Parameters) -> Self::Strategy {
        (
            any::<[u8; 32]>(),
            any::<SuiAddress>(),
            vec(any::<Owner>(), 1..=max_num_gas_objects),
        )
            .prop_map(move |(seed, sender, owners)| generate_random_gas_data(seed, sender, owners))
            .boxed()
    }
}
