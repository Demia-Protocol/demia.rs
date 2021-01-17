// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! cargo run --example search_address --release
use iota::{api::search_address, Client, Seed};
#[macro_use]
extern crate dotenv_codegen;

/// In this example we try to find the index of an address from a seed.
#[tokio::main]
async fn main() {
    let iota = Client::build() // Crate a client instance builder
        .with_node("http://0.0.0.0:14265") // Insert the node here
        .unwrap()
        .finish()
        .unwrap();

    let seed = Seed::from_ed25519_bytes(&hex::decode(dotenv!("seed")).unwrap()).unwrap(); // Insert your seed

    let address = iota
        .find_addresses(&seed)
        .with_account_index(0)
        .with_range(9..10)
        .finish()
        .unwrap();
    println!("{:?}", address);
    let res = search_address(&seed, 0, 0..10, &address[0]).unwrap();
    println!(
        "Found address with address_index: {}, internal address: {}",
        res.0, res.1
    );
}
