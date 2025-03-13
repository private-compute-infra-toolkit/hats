// Copyright 2025 Google LLC
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

use crate::{Error, SecretSplit};
use anyhow::Result;
use num_bigint::{BigInt, RandBigInt, Sign};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct ShamirSharing {
    threshold: usize,
    numshares: usize,
    prime: BigInt,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Share {
    pub(crate) value: Vec<u8>,
    pub(crate) index: usize,
}

pub fn get_prime() -> BigInt {
    // 512 bit prime number from https://neuromancer.sk/std/other/ssc-512#
    BigInt::parse_bytes(
        b"C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B235A2359C4AFBC9EB7987F1C9AB37E42599188C4B7DC6269B830D80897F57A5F71",
        16,
    )
    .unwrap()
}

impl ShamirSharing {
    pub fn new(numshares: usize, threshold: usize, prime: BigInt) -> Result<Self, Error> {
        if numshares < 2 || threshold < 2 {
            return Err(Error::MustSplitTrust);
        }
        if numshares < threshold {
            return Err(Error::ThresholdGreaterThanNumShares);
        }
        Ok(Self {
            numshares,
            threshold,
            prime,
        })
    }
}

const LABEL: &[u8; 4] = b"hats";

impl SecretSplit for ShamirSharing {
    fn split(&self, secret_bytes: &[u8]) -> Result<Vec<String>, Error> {
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
        let mut output: Vec<String> = Vec::new();
        for x in 1..=self.numshares {
            let serialized_share = serde_json::to_string(&Share {
                value: eval(poly.clone(), x, &self.prime),
                index: x,
            })
            .map_err(|_| Error::SerializationFailure)?;
            output.push(serialized_share);
        }
        Ok(output)
    }

    fn recover(&self, serialized_shares: &[&[u8]]) -> Result<Vec<u8>, Error> {
        if serialized_shares.len() < 2 {
            return Err(Error::MustSplitTrust);
        }
        if serialized_shares.len() < self.threshold {
            return Err(Error::BelowThreshold);
        }
        let mut indices: Vec<usize> = Vec::new();
        let mut shares_bytes: Vec<Vec<u8>> = Vec::new();
        for serialized_share in serialized_shares.iter().take(self.threshold) {
            let share = deserialize_share(serialized_share)?;
            indices.push(share.index);
            shares_bytes.push(share.value.clone());
        }
        let sum: BigInt = interpolate(indices, shares_bytes, &self.prime);
        let result = if sum < BigInt::from(0) {
            (sum + &self.prime).to_bytes_be().1
        } else {
            sum.to_bytes_be().1
        };
        remove_label(result)
    }
}

fn deserialize_share(serialized_share: &[u8]) -> Result<Share, Error> {
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

fn not_in_range_prime(bi_key: &BigInt, prime: &BigInt) -> bool {
    bi_key >= prime || *bi_key < BigInt::from(0)
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
    use crate::interface::shamir_recover_wrap;
    use crate::interface::shamir_split_wrap;
    use crate::xor_sharing;
    use bssl_crypto::hpke;
    use crypto::P256Scalar;

    fn get_valid_private_key() -> Vec<u8> {
        let kem = hpke::Kem::X25519HkdfSha256;
        let (_, private) = kem.generate_keypair();
        private.to_vec()
    }

    #[test]
    fn test_shamir2of3() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        let secret = get_valid_private_key();
        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret12 = sham.recover(&shares[0..2]).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3]).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2], shares[0]];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn test_shamir3of5() {
        let sham = ShamirSharing::new(5, 3, get_prime()).unwrap();

        let secret = get_valid_private_key();

        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret123 = sham.recover(&shares[0..3]).unwrap();
        let recovered_secret234 = sham.recover(&shares[1..4]).unwrap();
        let recovered_secret345 = sham.recover(&shares[2..5]).unwrap();
        assert_eq!(secret, recovered_secret123);
        assert_eq!(secret, recovered_secret234);
        assert_eq!(secret, recovered_secret345);

        let shares152 = vec![shares[0], shares[4], shares[1]];
        let recovered_secret152 = sham.recover(&shares152).unwrap();
        assert_eq!(secret, recovered_secret152);
    }

    #[test]
    fn test_shamir4of4() {
        let sham = ShamirSharing::new(4, 4, get_prime()).unwrap();

        let secret = get_valid_private_key();

        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret);

        let shares = vec![shares[0], shares[3], shares[2], shares[1]];
        let recovered_secret_unordered = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret_unordered);
    }

    #[test]
    fn test_more_than_threshold() {
        let sham = ShamirSharing::new(5, 2, get_prime()).unwrap();

        let secret = get_valid_private_key();

        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret123 = sham.recover(&shares[0..3]).unwrap();
        let recovered_secret2345 = sham.recover(&shares[1..5]).unwrap();
        let recovered_secret_all = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret123);
        assert_eq!(secret, recovered_secret2345);
        assert_eq!(secret, recovered_secret_all);

        let shares1524 = vec![shares[0], shares[4], shares[1], shares[3]];
        let recovered_secret1524 = sham.recover(&shares1524).unwrap();
        assert_eq!(secret, recovered_secret1524);
    }

    #[test]
    fn test_errors() {
        assert_eq!(
            ShamirSharing::new(2, 3, get_prime()).unwrap_err(),
            Error::ThresholdGreaterThanNumShares
        );

        assert_eq!(
            ShamirSharing::new(1, 1, get_prime()).unwrap_err(),
            Error::MustSplitTrust
        );

        let sham = ShamirSharing {
            threshold: 3,
            numshares: 5,
            prime: get_prime(),
        };

        let secret_bytes = get_valid_private_key();

        let splits = sham.split(&secret_bytes).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();
        let e = sham.recover(&shares[0..2]).unwrap_err();
        assert_eq!(e, Error::BelowThreshold);
    }

    #[test]
    fn test_shamir4of4_wrap() {
        let secret = get_valid_private_key();

        let shares = shamir_split_wrap(&secret, /*numshares=*/ 4, /*threshold=*/ 4).unwrap();

        let recovered_secret =
            shamir_recover_wrap(&shares, /*numshares=*/ 4, /*threshold=*/ 4).unwrap();
        assert_eq!(secret, recovered_secret);
    }

    #[test]
    fn test_shamir_encrypted_secret_size() {
        let sham = ShamirSharing::new(4, 4, get_prime()).unwrap();

        // 65bytes = 520bits, need to shorten
        // using public key here to represent an encrypted secret > 32 bytes
        let public: [u8; 60] = P256Scalar::generate().compute_public_key()[5..]
            .try_into()
            .unwrap();
        let secret = public.to_vec();
        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret = sham.recover(&shares).unwrap();
        assert_eq!(secret, recovered_secret);
    }

    #[test]
    fn secret_with_leading_zeros() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        let secret =
            hex::decode("00000000000000000000000000000000000000000000dc663a8ceba6108c0840")
                .unwrap();
        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret12 = sham.recover(&shares[0..2]).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3]).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2], shares[0]];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn secret_all_zeros() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        let secret =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let splits = sham.split(&secret).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        let recovered_secret12 = sham.recover(&shares[0..2]).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3]).unwrap();
        assert_eq!(secret, recovered_secret12);
        assert_eq!(secret, recovered_secret23);

        let shares31 = vec![shares[2], shares[0]];
        let recovered_secret31 = sham.recover(&shares31).unwrap();
        assert_eq!(secret, recovered_secret31);
    }

    #[test]
    fn recover_malformed_secret_error() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        assert_eq!(sham.recover(&[&serde_json::to_string(&Share {
        value: hex::decode("64bb92a1cb8933d951d8ab8a75e8089ba1ddac8d89266dc59ae4dc2e2670d35f970fc784405c01453f4eaf539fe6ad9a0c401433d9652856f53cb50ea4a54fb0").unwrap(),
        index: 1,
        }).unwrap().into_bytes(),
        &serde_json::to_string(&Share {
            value: hex::decode("6522dd434132d95730c3a013e0dbfd01bc96b7a0110b7cdccea2d5e4383edefb6b0bfcc811576518256cf1602c35c674933777e3afcd0f4caede1693f7a4ccb7").unwrap(),
            index: 3,
        }).unwrap().into_bytes(),
        ]).unwrap_err(), Error::MalformedSecret);
    }

    #[test]
    fn shamir_mixed_share_error() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        assert_eq!(sham.recover(&[&serde_json::to_string(&Share {
            value: hex::decode("64bb92a1cb8933d951d8ab8a75e8089ba1ddac8d89266dc59ae4dc2e2670d35f970fc784405c01453f4eaf539fe6ad9a0c401433d9652856f53cb50ea4a54fb0").unwrap(),
            index: 1,
            }).unwrap().into_bytes(),
            &serde_json::to_string(&xor_sharing::Share {
                value: hex::decode("6522dd434132d95730c3a013e0dbfd01bc96b7a0110b7cdccea2d5e4383edefb6b0bfcc811576518256cf1602c35c674933777e3afcd0f4caede1693f7a4ccb7").unwrap(),
            }).unwrap().into_bytes(),
            ]).unwrap_err(), Error::NotAShareObject);
    }

    #[test]
    fn recover_not_enough_splits_error() {
        let sham = ShamirSharing::new(3, 2, get_prime()).unwrap();

        assert_eq!(sham.recover(&[]).unwrap_err(), Error::MustSplitTrust);
        assert_eq!(sham.recover(&[&serde_json::to_string(&Share {
            value: hex::decode("64bb92a1cb8933d951d8ab8a75e8089ba1ddac8d89266dc59ae4dc2e2670d35f970fc784405c01453f4eaf539fe6ad9a0c401433d9652856f53cb50ea4a54fb0").unwrap(),
            index: 1,
            }).unwrap().into_bytes()]).unwrap_err(), Error::MustSplitTrust);
    }
}
