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
use num_bigint::{BigInt, RandBigInt, Sign};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct SecretSharing {
    pub threshold: usize,
    pub numshares: usize,
    pub prime: BigInt,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Share {
    pub index: usize,
    value: Vec<u8>,
    wrapped: bool,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BelowThreshold,
    ThresholdGreaterThanNumShares,
    MustSplitTrust,
    SecretMustBeInRangePrime,
    ImproperCoeffs,
    NotAShareObject,
    MalformedSecret,
}

// Do not use cxx:bridge if `noffi` is enabled. This is to avoid
// linking against C++ standard and cxx libraries in pure rust code.
#[cfg(not(feature = "noffi"))]
#[cxx::bridge(namespace = "privacy_sandbox::crypto")]
mod ffi {
    pub struct SecretSharing {
        pub threshold: usize,
        pub numshares: usize,
    }

    extern "Rust" {
        #[cxx_name = "SplitSecret"]
        fn split_wrap(
            secret_bytes: &[u8],
            numshares: usize,
            threshold: usize,
            wrapped: bool,
        ) -> Result<Vec<String>>;

        #[cxx_name = "RecoverSecret"]
        fn recover_wrap(
            shares_vec: &Vec<String>,
            numshares: usize,
            threshold: usize,
        ) -> Result<Vec<u8>>;
    }
}

#[cfg(not(feature = "noffi"))]
pub fn split_wrap(
    secret_bytes: &[u8],
    numshares: usize,
    threshold: usize,
    wrapped: bool,
) -> Result<Vec<String>, String> {
    let sham = SecretSharing {
        numshares: numshares,
        threshold: threshold,
        prime: get_prime(),
    };
    let shares = sham
        .split(secret_bytes, wrapped)
        .map_err(|err| format!("Error splitting secret: {:#?}", err))?;
    let mut serialized_shares: Vec<String> = Vec::new();
    for share in shares {
        let ser_share = serde_json::to_string(&share)
            .map_err(|err| format!("Error splitting secret: {err}"))?;
        serialized_shares.push(ser_share);
    }
    Ok(serialized_shares)
}

#[cfg(not(feature = "noffi"))]
pub fn recover_wrap(
    shares_vec: &Vec<String>,
    numshares: usize,
    threshold: usize,
) -> Result<Vec<u8>, String> {
    let sham = SecretSharing {
        numshares: numshares,
        threshold: threshold,
        prime: get_prime(),
    };

    let mut shares: Vec<Share> = Vec::new();
    for ser_share in shares_vec {
        let share: Share =
            serde_json::from_value(serde_json::from_str(ser_share).unwrap()).unwrap();
        shares.push(share);
    }
    sham.recover(&shares)
        .map_err(|_| "Error recovering secrets".to_string())
}

pub fn desearialize_share(serialized_share: &Vec<u8>) -> Result<Share, Error> {
    let string: String =
        String::from_utf8(serialized_share.to_vec()).map_err(|_| Error::NotAShareObject)?;
    let share: Share = serde_json::from_value(serde_json::from_str(&string).unwrap())
        .map_err(|_| Error::NotAShareObject)?;
    Ok(share)
}

fn eval(poly: Vec<BigInt>, x: usize, prime: &BigInt) -> Vec<u8> {
    let x_b: BigInt = BigInt::from(x);
    let mut total: BigInt = BigInt::from(0u32);
    for coeff in poly.into_iter().rev() {
        total *= &x_b;
        total += coeff;
        total %= prime;
    }
    total.to_bytes_be().1
}

fn interpolate(indices: Vec<usize>, shares: Vec<Vec<u8>>, prime: &BigInt) -> BigInt {
    let x = BigInt::from(0);
    let mut sum = BigInt::from(0);
    let shares_bi: Vec<BigInt> = shares
        .iter()
        .map(|x| BigInt::from_bytes_be(Sign::Plus, x))
        .collect();
    let indices_bi: Vec<BigInt> = indices.iter().map(|x| BigInt::from(*x)).collect();
    for i in 0..shares.len() {
        let mut num = BigInt::from(1);
        let mut denom = BigInt::from(1);
        for j in 0..shares.len() {
            if i != j {
                num = num * (&x - &indices_bi[j]) % prime;
                denom = denom * (&indices_bi[i] - &indices_bi[j]) % prime;
            }
        }
        denom = ((denom % prime) + prime) % prime;
        denom = mod_inv(denom, prime.clone());
        sum = (sum + num * denom * &shares_bi[i]) % prime;
    }
    sum
}

// extended euclidean algorithm for finding the modular inverse
fn mod_inv(num: BigInt, prime: BigInt) -> BigInt {
    let (mut r, mut next_r, mut t, mut next_t) =
        (prime.clone(), num.clone(), BigInt::from(0), BigInt::from(1));
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

pub fn get_prime() -> BigInt {
    // 512 bit prime number from https://neuromancer.sk/std/other/ssc-512#
    BigInt::parse_bytes(
        b"C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B235A2359C4AFBC9EB7987F1C9AB37E42599188C4B7DC6269B830D80897F57A5F71",
        16,
    )
    .unwrap()
}

fn not_in_range_prime(bi_key: &BigInt, prime: &BigInt) -> bool {
    bi_key >= prime || *bi_key < BigInt::from(0)
}

const LABEL: &[u8; 4] = b"hats";

impl SecretSharing {
    pub fn split(&self, secret_bytes: &[u8], wrapped: bool) -> Result<Vec<Share>, Error> {
        if self.numshares < self.threshold {
            return Err(Error::ThresholdGreaterThanNumShares);
        }
        if self.numshares < 2 || self.threshold < 2 {
            return Err(Error::MustSplitTrust);
        }
        let secret = BigInt::from_bytes_be(Sign::Plus, &[LABEL, secret_bytes].concat());
        if not_in_range_prime(&secret, &self.prime) {
            return Err(Error::SecretMustBeInRangePrime);
        }
        let mut poly: Vec<BigInt> = vec![secret.clone()];
        let mut rng = rand::thread_rng();
        let low = BigInt::from(1);
        for _ in 0..(self.threshold - 1) {
            poly.push(rng.gen_bigint_range(&low, &self.prime));
        }
        if poly.len() == 1 {
            return Err(Error::ImproperCoeffs);
        }
        let mut output: Vec<Share> = Vec::new();
        for x in 1..=self.numshares {
            output.push(Share {
                value: eval(poly.clone(), x, &self.prime),
                index: x,
                wrapped: wrapped,
            });
        }
        Ok(output)
    }

    pub fn recover(&self, shares: &[Share]) -> Result<Vec<u8>, Error> {
        if shares.len() < self.threshold.try_into().unwrap() {
            return Err(Error::BelowThreshold);
        }
        let mut indices: Vec<usize> = Vec::new();
        let mut share: Vec<Vec<u8>> = Vec::new();
        for i in 0..self.threshold.clone() {
            indices.push(shares[i].index.clone());
            share.push(shares[i].value.clone());
        }
        let sum: BigInt = interpolate(indices, share, &self.prime);
        let result = if sum < BigInt::from(0) {
            (sum + &self.prime).to_bytes_be().1
        } else {
            sum.to_bytes_be().1
        };
        remove_label(result)
    }
}

fn remove_label(secret_with_size: Vec<u8>) -> Result<Vec<u8>, Error> {
    if secret_with_size.len() <= 4 {
        return Err(Error::MalformedSecret);
    }
    Ok(secret_with_size[4..].to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use bssl_crypto::hpke;
    use crypto::P256Scalar;

    fn get_valid_private_key() -> Vec<u8> {
        let kem = hpke::Kem::X25519HkdfSha256;
        let (_, private) = kem.generate_keypair();
        private.to_vec()
    }

    #[test]
    fn test_shamir2of3() {
        let sham = SecretSharing {
            threshold: 2,
            numshares: 3,
            prime: get_prime(),
        };

        let secret = get_valid_private_key();
        let shares = sham.split(&secret, false).unwrap();

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
        let sham = SecretSharing {
            threshold: 3,
            numshares: 5,
            prime: get_prime(),
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret, false).unwrap();

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
        let sham = SecretSharing {
            threshold: 4,
            numshares: 4,
            prime: get_prime(),
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret, false).unwrap();

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
        let sham = SecretSharing {
            threshold: 2,
            numshares: 5,
            prime: get_prime(),
        };

        let secret = get_valid_private_key();

        let shares = sham.split(&secret, false).unwrap();

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
        let sham = SecretSharing {
            threshold: 3,
            numshares: 2,
            prime: get_prime(),
        };

        let e = sham.split(&secret, false).unwrap_err();
        assert_eq!(e, Error::ThresholdGreaterThanNumShares);

        let sham = SecretSharing {
            threshold: 1,
            numshares: 1,
            prime: get_prime(),
        };
        let e = sham.split(&secret, false).unwrap_err();
        assert_eq!(e, Error::MustSplitTrust);

        let sham = SecretSharing {
            threshold: 3,
            numshares: 5,
            prime: get_prime(),
        };

        let secret_bytes = get_valid_private_key();

        let shares = sham.split(&secret_bytes, false).unwrap();
        let e = sham.recover(&shares[0..2].to_vec()).unwrap_err();
        assert_eq!(e, Error::BelowThreshold);
    }

    #[test]
    fn test_shamir4of4_wrap() {
        let secret = get_valid_private_key();

        let shares = split_wrap(&secret, /*numshares=*/ 4, /*threshold=*/ 4, false).unwrap();

        let recovered_secret = recover_wrap(&shares, /*numshares=*/ 4, /*threshold=*/ 4).unwrap();
        assert_eq!(secret, recovered_secret);
    }

    #[test]
    fn test_shamir_encrypted_secret_size() {
        let sham = SecretSharing {
            threshold: 4,
            numshares: 4,
            prime: get_prime(),
        };

        // 65bytes = 520bits, need to shorten
        // using public key here to represent an encrypted secret > 32 bytes
        let public: [u8; 60] = P256Scalar::generate().compute_public_key()[5..]
            .try_into()
            .unwrap();
        let secret = public.to_vec();
        let shares = sham.split(&secret, false).unwrap();

        let recovered_secret = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret);
    }

    #[test]
    fn secret_with_leading_zeros() {
        let sham = SecretSharing {
            threshold: 2,
            numshares: 3,
            prime: get_prime(),
        };

        let secret =
            hex::decode("00000000000000000000000000000000000000000000dc663a8ceba6108c0840")
                .unwrap();
        let shares = sham.split(&secret, false).unwrap();

        let recovered_secret12 = sham.recover(&shares[0..2].to_vec()).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3].to_vec()).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2].clone(), shares[0].clone()];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn secret_all_zeros() {
        let sham = SecretSharing {
            threshold: 2,
            numshares: 3,
            prime: get_prime(),
        };

        let secret =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let shares = sham.split(&secret, false).unwrap();

        let recovered_secret12 = sham.recover(&shares[0..2].to_vec()).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3].to_vec()).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2].clone(), shares[0].clone()];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn recover_malformed_secret_error() {
        let sham = SecretSharing {
            threshold: 2,
            numshares: 3,
            prime: get_prime(),
        };

        assert_eq!(sham.recover(&[Share {
        index: 1,
        value: hex::decode("64bb92a1cb8933d951d8ab8a75e8089ba1ddac8d89266dc59ae4dc2e2670d35f970fc784405c01453f4eaf539fe6ad9a0c401433d9652856f53cb50ea4a54fb0").unwrap(),
        wrapped: false,
        },
        Share {
            index: 3,
            value: hex::decode("6522dd434132d95730c3a013e0dbfd01bc96b7a0110b7cdccea2d5e4383edefb6b0bfcc811576518256cf1602c35c674933777e3afcd0f4caede1693f7a4ccb7").unwrap(),
            wrapped: false,
        },
        ]).unwrap_err(), Error::MalformedSecret);
    }
}
