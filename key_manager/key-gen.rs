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
    Random256Key,
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
    #[arg(long, required = false, default_value = "false")]
    wrap: bool,
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

fn generate_random256key() -> String {
    let mut random256key = [0u8; 32];
    crypto::rand_bytes(&mut random256key);
    hex::encode(random256key)
}

fn main() {
    let (public_key, private_key) = match Args::parse().key_type {
        KeyType::Secp128r1 => {
            let (public_key, private_key) = generate_secp128r1_keypairs();
            (Some(public_key), private_key)
        }
        KeyType::X25519HkdfSha256 => {
            let (public_key, private_key) = generate_x25519hkdfsha256_keypairs();
            (Some(public_key), private_key)
        }
        KeyType::Random256Key => (None, generate_random256key()),
    };

    if let Some(public_key) = public_key {
        println!("Public: {}", public_key);
    }
    println!("Private: {}", private_key);
    let secret = if Args::parse().wrap {
        let wrapping_key = hex::decode(&generate_random256key()).unwrap();
        let nonce = [0u8; 12];
        let aad = [0u8; 16];
        let plaintext = hex::decode(&private_key).unwrap();
        let mut ciphertext = plaintext.clone();
        println!("Wrapping: {}", hex::encode(wrapping_key.clone()));
        // Encrypt the private_key with wrapping key
        crypto::aes_256_gcm_seal_in_place(
            &wrapping_key.try_into().unwrap(),
            &nonce,
            &aad,
            &mut ciphertext,
        );
        hex::encode(ciphertext)
    } else {
        private_key
    };

    if Args::parse().split {
        let mut sham = SecretSharing {
            numshares: Args::parse().numshares,
            threshold: Args::parse().threshold,
            prime: secret_sharing::get_prime(),
        };
        let shares = sham.split(&hex::decode(secret).unwrap(), false).unwrap();
        for share in shares {
            println!(
                "Share[{}]: {}",
                share.index,
                hex::encode(serde_json::to_string(&share).unwrap())
            );
        }
    }
}
