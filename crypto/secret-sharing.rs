// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
extern crate alloc;

use anyhow::Result;
use bssl_crypto::hpke;
use num_bigint::{BigInt, RandBigInt};
use serde::Deserialize;
use serde_json::json;

pub const HPKE_PRIVATE_KEY_LENGTH: usize = 32;

#[derive(Clone)]
pub struct SecretSharing {
    pub threshold: usize,
    pub numshares: usize,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Share {
    value: BigInt,
    index: BigInt,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BelowThreshold,
    ThresholdGreaterThanNumShares,
    MustSplitTrust,
    SecretMustBeInRangePrime,
    ImproperCoeffs,
}

#[cxx::bridge(namespace = "privacy_sandbox::secret_sharing")]
mod ffi {
    pub struct SecretSharing {
        pub threshold: usize,
        pub numshares: usize,
    }
    extern "Rust" {
        pub fn split_wrap(
            secret_bytes: &[u8; 32],
            numshares: usize,
            threshold: usize,
        ) -> Result<Vec<String>>;
        pub fn recover_wrap(
            shares1: &Vec<String>,
            numshares: usize,
            threshold: usize,
        ) -> Result<[u8; 32]>;
        pub fn get_valid_private_key() -> [u8; 32];
    }
}

pub fn split_wrap(
    secret_bytes: &[u8; HPKE_PRIVATE_KEY_LENGTH],
    numshares: usize,
    threshold: usize,
) -> Result<Vec<String>, String> {
    let mut sham = SecretSharing {
        numshares: numshares,
        threshold: threshold,
    };
    let shares = sham.split(secret_bytes).unwrap();
    let mut shares1: Vec<String> = Vec::new();
    for share in shares {
        let serialized_share = json!({
            "value": share.value,
            "index": share.index,
        });
        shares1.push(serialized_share.to_string());
    }
    Ok(shares1)
}

pub fn recover_wrap(
    shares1: &Vec<String>,
    numshares: usize,
    threshold: usize,
) -> Result<[u8; HPKE_PRIVATE_KEY_LENGTH], String> {
    let mut sham = SecretSharing {
        numshares: numshares,
        threshold: threshold,
    };

    let mut shares: Vec<Share> = Vec::new();
    for ser_share1 in shares1 {
        let share1: Share =
            serde_json::from_value(serde_json::from_str(ser_share1).unwrap()).unwrap();
        shares.push(share1);
    }
    let key = sham.recover(&shares).unwrap();
    Ok(key)
}

pub fn get_valid_private_key() -> [u8; HPKE_PRIVATE_KEY_LENGTH] {
    let kem = hpke::Kem::X25519HkdfSha256;
    let (mut private, _) = kem.generate_keypair();
    let mut bi_priv = BigInt::from_signed_bytes_be(&private);
    while not_in_range_prime(&bi_priv) {
        (private, _) = kem.generate_keypair();
        bi_priv = BigInt::from_signed_bytes_be(&private);
    }
    private.try_into().unwrap()
}

fn eval(poly: Vec<BigInt>, x: usize) -> BigInt {
    let prime = get_prime();
    let x_b: BigInt = BigInt::from(x);
    let mut total: BigInt = BigInt::from(0u32);
    for coeff in poly.into_iter().rev() {
        total *= &x_b;
        total += coeff;
        total %= &prime;
    }
    total
}

fn interpolate(indices: Vec<BigInt>, shares: Vec<BigInt>) -> BigInt {
    let x = BigInt::from(0);
    let prime = get_prime();
    let mut sum = BigInt::from(0);
    for i in 0..shares.len() {
        let mut num = BigInt::from(1);
        let mut denom = BigInt::from(1);
        for j in 0..shares.len() {
            if i != j {
                num = num * (&x - &indices[j]) % &prime;
                denom = denom * (&indices[i] - &indices[j]) % &prime;
            }
        }
        denom = ((denom % &prime) + &prime) % &prime;
        denom = mod_inv(denom);
        sum = (sum + num * denom * &shares[i]) % &prime;
    }
    sum
}

// extended euclidean algorithm for finding the modular inverse
fn mod_inv(num: BigInt) -> BigInt {
    let (mut r, mut next_r, mut t, mut next_t) =
        (get_prime(), num.clone(), BigInt::from(0), BigInt::from(1));
    let mut quotient;
    let mut tmp;
    while next_r > BigInt::from(0) {
        quotient = r.clone() / next_r.clone();
        tmp = next_r.clone();
        next_r = r.clone() - next_r.clone() * quotient.clone();
        r = tmp.clone();
        tmp = next_t.clone();
        next_t = t - next_t * quotient;
        t = tmp;
    }
    t
}

fn get_prime() -> BigInt {
    BigInt::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .unwrap()
}

fn not_in_range_prime(bi_key: &BigInt) -> bool {
    let prime = get_prime();
    let zero = BigInt::from(0);
    *bi_key >= prime || *bi_key < zero
}

impl SecretSharing {
    pub fn split(
        &mut self,
        secret_bytes: &[u8; HPKE_PRIVATE_KEY_LENGTH],
    ) -> Result<Vec<Share>, Error> {
        let prime = get_prime();
        if self.numshares < self.threshold {
            return Err(Error::ThresholdGreaterThanNumShares);
        }
        if self.numshares < 2 || self.threshold < 2 {
            return Err(Error::MustSplitTrust);
        }
        let secret = BigInt::from_signed_bytes_be(secret_bytes);
        if not_in_range_prime(&secret) {
            return Err(Error::SecretMustBeInRangePrime);
        }
        let mut poly: Vec<BigInt> = vec![secret.clone()];
        let mut rng = rand::thread_rng();
        let low = BigInt::from(1);
        for _ in 0..(self.threshold - 1) {
            poly.push(rng.gen_bigint_range(&low, &prime));
        }
        if poly.len() == 1 {
            return Err(Error::ImproperCoeffs);
        }
        let mut output: Vec<Share> = Vec::new();
        for x in 1..=self.numshares {
            output.push(Share {
                value: eval(poly.clone(), x),
                index: BigInt::from(x),
            });
        }
        Ok(output)
    }

    pub fn recover(&mut self, shares: &Vec<Share>) -> Result<[u8; HPKE_PRIVATE_KEY_LENGTH], Error> {
        let prime = get_prime();
        if shares.len() < self.threshold.try_into().unwrap() {
            return Err(Error::BelowThreshold);
        }
        let mut indices: Vec<BigInt> = Vec::new();
        let mut share: Vec<BigInt> = Vec::new();
        for i in 0..self.threshold.clone() {
            indices.push(shares[i].index.clone());
            share.push(shares[i].value.clone());
        }
        let sum: BigInt = interpolate(indices, share);
        if sum < BigInt::from(0) {
            Ok((sum + &prime).to_signed_bytes_be().try_into().unwrap())
        } else {
            Ok(sum.to_signed_bytes_be().try_into().unwrap())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_shamir2of3() {
        let mut sham = SecretSharing {
            threshold: 2,
            numshares: 3,
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret).unwrap();

        let recovered_secret12 = sham.recover(&shares[0..2].to_vec()).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3].to_vec()).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2].clone(), shares[0].clone()];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn test_shamir3of5() {
        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 5,
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret).unwrap();

        let recovered_secret123 = sham.recover(&shares[0..3].to_vec()).unwrap();
        let recovered_secret234 = sham.recover(&shares[1..4].to_vec()).unwrap();
        let recovered_secret345 = sham.recover(&shares[2..5].to_vec()).unwrap();
        assert_eq!(secret, recovered_secret123);
        assert_eq!(secret, recovered_secret234);
        assert_eq!(secret, recovered_secret345);

        let shares152 = vec![shares[0].clone(), shares[4].clone(), shares[1].clone()];
        let recovered_secret152 = sham.recover(&shares152).unwrap();
        assert_eq!(secret, recovered_secret152);
    }

    #[test]
    fn test_shamir4of4() {
        let mut sham = SecretSharing {
            threshold: 4,
            numshares: 4,
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret).unwrap();

        let recovered_secret = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret);

        let shares = vec![
            shares[0].clone(),
            shares[3].clone(),
            shares[2].clone(),
            shares[1].clone(),
        ];
        let recovered_secret_unordered = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret_unordered);
    }

    #[test]
    fn test_more_than_threshold() {
        let mut sham = SecretSharing {
            threshold: 2,
            numshares: 5,
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret).unwrap();

        let recovered_secret123 = sham.recover(&shares[0..3].to_vec()).unwrap();
        let recovered_secret2345 = sham.recover(&shares[1..5].to_vec()).unwrap();
        let recovered_secret_all = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret123);
        assert_eq!(secret, recovered_secret2345);
        assert_eq!(secret, recovered_secret_all);

        let shares1524 = vec![
            shares[0].clone(),
            shares[4].clone(),
            shares[1].clone(),
            shares[3].clone(),
        ];
        let recovered_secret1524 = sham.recover(&shares1524).unwrap();
        assert_eq!(secret, recovered_secret1524);
    }

    #[test]
    fn test_errors() {
        let secret = get_valid_private_key();
        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 2,
        };

        let e = sham.split(&secret).unwrap_err();
        assert_eq!(e, Error::ThresholdGreaterThanNumShares);

        sham = SecretSharing {
            threshold: 1,
            numshares: 1,
        };
        let e = sham.split(&secret).unwrap_err();
        assert_eq!(e, Error::MustSplitTrust);

        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 5,
        };

        let secret_bytes = get_valid_private_key();

        let shares = sham.split(&secret_bytes).unwrap();
        let e = sham.recover(&shares[0..2].to_vec()).unwrap_err();
        assert_eq!(e, Error::BelowThreshold);
    }

    #[test]
    fn test_shamir4of4_wrap() {
        let sham = SecretSharing {
            threshold: 4,
            numshares: 4,
        };

        let secret = get_valid_private_key();

        let shares = split_wrap(&secret, sham.numshares, sham.threshold).unwrap();

        let recovered_secret = recover_wrap(&shares, sham.numshares, sham.threshold).unwrap();
        assert_eq!(secret, recovered_secret);
    }
}
