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
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct XorSharing {
    numshares: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Share {
    pub(crate) value: Vec<u8>,
}

impl XorSharing {
    pub fn new(numshares: usize) -> Result<Self, Error> {
        if numshares < 2 {
            return Err(Error::MustSplitTrust);
        }
        Ok(Self { numshares })
    }
}

impl SecretSplit for XorSharing {
    fn split(&self, secret_bytes: &[u8]) -> Result<Vec<String>, Error> {
        let mut xor_result = secret_bytes.to_vec();
        let mut shares = Vec::with_capacity(self.numshares);

        for _ in 0..(self.numshares - 1) {
            let mut random_bytes = vec![0u8; secret_bytes.len()];
            crypto::rand_bytes(&mut random_bytes);

            xor_result = xor(&xor_result, &random_bytes)?;
            let serialized_share = serde_json::to_string(&Share {
                value: random_bytes,
            })
            .map_err(|_| Error::SerializationFailure)?;
            shares.push(serialized_share);
        }

        shares.push(serde_json::to_string(&Share { value: xor_result }).unwrap());
        Ok(shares)
    }

    fn recover(&self, serialized_shares: &[&[u8]]) -> Result<Vec<u8>, Error> {
        if serialized_shares.len() != self.numshares {
            return Err(Error::NumSharesMismatch);
        }

        let mut reconstructed = deserialize_share(serialized_shares[0])?.value;

        for serialized_share in serialized_shares.iter().skip(1) {
            let share = deserialize_share(serialized_share)?;
            reconstructed = xor(&reconstructed, &share.value)?;
        }
        Ok(reconstructed)
    }
}

fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    if a.len() != b.len() {
        return Err(Error::MalformedSecret);
    }

    Ok(a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect())
}

fn deserialize_share(serialized_share: &[u8]) -> Result<Share, Error> {
    let string: String =
        String::from_utf8(serialized_share.to_vec()).map_err(|_| Error::NotAShareObject)?;
    let share: Share = serde_json::from_value(serde_json::from_str(&string).unwrap())
        .map_err(|_| Error::NotAShareObject)?;
    Ok(share)
}

#[cfg(test)]
mod test {
    use super::*;
    use bssl_crypto::hpke;

    fn get_valid_private_key() -> Vec<u8> {
        let kem = hpke::Kem::X25519HkdfSha256;
        let (_, private) = kem.generate_keypair();
        private.to_vec()
    }

    #[test]
    fn mixed_share_xor_error() {
        let xor = XorSharing::new(2).unwrap();

        assert_eq!(xor.recover(&[&serde_json::to_string(&Share {
            value: hex::decode("03edb86998129fb78e2a1ececde5af0ac74d5b1a5e41872d50c602072e21f9b0").unwrap(),
            }).unwrap().into_bytes(),
            &serde_json::to_string(&crate::shamir_sharing::Share {
                value: hex::decode("6522dd434132d95730c3a013e0dbfd01bc96b7a0110b7cdccea2d5e4383edefb6b0bfcc811576518256cf1602c35c674933777e3afcd0f4caede1693f7a4ccb7").unwrap(),
                index: 1,
            }).unwrap().into_bytes(),
            ]).unwrap_err(), Error::MalformedSecret);
    }

    #[test]
    fn test_xor_split_1() {
        assert_eq!(XorSharing::new(1).unwrap_err(), Error::MustSplitTrust);
    }

    #[test]
    fn test_xor_split_mismatch() {
        let xor5 = XorSharing::new(5).unwrap();

        let message = get_valid_private_key();
        let splits = xor5.split(&message).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        assert_eq!(shares.len(), 5);

        let xor4 = XorSharing::new(4).unwrap();
        assert_eq!(xor4.recover(&shares).unwrap_err(), Error::NumSharesMismatch);
    }

    #[test]
    fn test_xor_split_2() {
        let xor = XorSharing::new(2).unwrap();

        let message = get_valid_private_key();
        let splits = xor.split(&message).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        assert_eq!(shares.len(), 2);

        let reconstructed = xor.recover(&shares).unwrap();
        assert_eq!(reconstructed, message);
    }

    #[test]
    fn test_xor_split_5() {
        let xor = XorSharing::new(5).unwrap();

        let message = get_valid_private_key();
        let splits = xor.split(&message).unwrap();
        let shares: Vec<&[u8]> = splits.iter().map(|s| s.as_bytes()).collect();

        assert_eq!(shares.len(), 5);

        let reconstructed = xor.recover(&shares).unwrap();
        assert_eq!(reconstructed, message);
    }

    #[test]
    fn test_xor_split_4() {
        let secret = get_valid_private_key();

        let shares = crate::interface::xor_split_wrap(&secret, /*numshares=*/ 4).unwrap();

        let recovered_secret =
            crate::interface::xor_recover_wrap(&shares, /*numshares=*/ 4).unwrap();
        assert_eq!(secret, recovered_secret);
    }

    #[test]
    fn test_xor_error() {
        let xor = XorSharing::new(2).unwrap();
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4];
        assert_eq!(
            xor.recover(&[
                &serde_json::to_string(&Share { value: a })
                    .unwrap()
                    .into_bytes(),
                &serde_json::to_string(&Share { value: b })
                    .unwrap()
                    .into_bytes(),
            ])
            .unwrap_err(),
            Error::MalformedSecret
        );
    }

    #[test]
    fn recover_not_enough_splits_error() {
        let xor = XorSharing::new(2).unwrap();

        assert_eq!(xor.recover(&[]).unwrap_err(), Error::NumSharesMismatch);
        assert_eq!(xor.recover(&[&serde_json::to_string(&Share {
            value: hex::decode("64bb92a1cb8933d951d8ab8a75e8089ba1ddac8d89266dc59ae4dc2e2670d35f970fc784405c01453f4eaf539fe6ad9a0c401433d9652856f53cb50ea4a54fb0").unwrap(),
            }).unwrap().into_bytes()]).unwrap_err(), Error::NumSharesMismatch);
    }
}
