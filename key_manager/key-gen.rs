// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::{Parser, ValueEnum};
use crypto::P256Scalar;
use hpke::{kem::X25519HkdfSha256, Kem, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use secret_sharing::SecretSharing;

#[derive(Default, Clone, ValueEnum)]
enum KeyType {
    #[default]
    Secp128r1,
    X25519HkdfSha256,
}

#[derive(Parser)]
struct Args {
    #[arg(long, required = false, value_enum, default_value_t = KeyType::default())]
    key_type: KeyType,
    #[arg(long, required = false, default_value = "false")]
    split: bool,
    #[arg(long, required = false, default_value = "3")]
    numshares: usize,
    #[arg(long, required = false, default_value = "2")]
    threshold: usize,
}

fn generate_secp128r1_keypairs() -> (String, String) {
    let private_key = P256Scalar::generate();
    let public_key = private_key.compute_public_key();
    (hex::encode(public_key), hex::encode(private_key.bytes()))
}

fn generate_x25519hkdfsha256_keypairs() -> (String, String) {
    let mut csprng = StdRng::from_entropy();
    let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut csprng);
    (
        hex::encode(public_key.to_bytes()),
        hex::encode(private_key.to_bytes()),
    )
}

fn main() {
    let (public_key, private_key) = match Args::parse().key_type {
        KeyType::Secp128r1 => generate_secp128r1_keypairs(),
        KeyType::X25519HkdfSha256 => generate_x25519hkdfsha256_keypairs(),
    };

    if Args::parse().split {
        let mut sham = SecretSharing {
            numshares: Args::parse().numshares,
            threshold: Args::parse().threshold,
            prime: secret_sharing::get_prime(),
        };
        let shares = sham
            .split(&hex::decode(private_key).unwrap(), false)
            .unwrap();
        println!("Public: {}", public_key);
        for share in shares {
            println!(
                "Share[{}]: {}",
                share.index,
                hex::encode(serde_json::to_string(&share).unwrap())
            );
        }
    } else {
        println!("Public: {}\nPrivate: {}", public_key, private_key);
    }
}
