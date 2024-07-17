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

use alloc::vec;
use alloc::vec::Vec;
use num_bigint::{BigInt, RandBigInt};

#[derive(Clone)]
pub struct SecretSharing {
    threshold: usize,
    numshares: usize,
}

#[derive(Clone, Debug)]
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

pub fn get_prime() -> BigInt {
    BigInt::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .unwrap()
}

impl SecretSharing {
    pub fn split(&mut self, secret_bytes: &Vec<u8>) -> Result<Vec<Share>, Error> {
        let prime = get_prime();
        if self.numshares < self.threshold {
            return Err(Error::ThresholdGreaterThanNumShares);
        }
        if self.numshares < 2 || self.threshold < 2 {
            return Err(Error::MustSplitTrust);
        }
        let secret = BigInt::from_signed_bytes_be(secret_bytes);
        if secret >= prime || secret < BigInt::from(0) {
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
                value: self.eval(poly.clone(), x),
                index: BigInt::from(x),
            });
        }
        Ok(output)
    }

    fn eval(&mut self, poly: Vec<BigInt>, x: usize) -> BigInt {
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

    pub fn recover(&mut self, shares: &[Share]) -> Result<Vec<u8>, Error> {
        let prime = get_prime();
        if shares.len() < self.threshold.try_into().unwrap() {
            return Err(Error::BelowThreshold);
        }
        let mut indices = Vec::new();
        let mut share = Vec::new();
        for i in 0..self.threshold.clone() {
            indices.push(shares[i].index.clone());
            share.push(shares[i].value.clone());
        }
        let sum: BigInt = self.interpolate(BigInt::from(0), indices, share);
        if sum < BigInt::from(0) {
            Ok((sum + &prime).to_signed_bytes_be())
        } else {
            Ok(sum.to_signed_bytes_be())
        }
    }

    fn interpolate(&mut self, x: BigInt, indices: Vec<BigInt>, shares: Vec<BigInt>) -> BigInt {
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
            denom = self.mod_inv(denom);
            sum = (sum + num * denom * &shares[i]) % &prime;
        }
        sum
    }

    // extended euclidean algorithm for finding the modular inverse
    fn mod_inv(&mut self, num: BigInt) -> BigInt {
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

        let mut rng = rand::thread_rng();
        let secret: BigInt = rng.gen_bigint_range(&BigInt::from(1), &get_prime());
        let secret_bytes = secret.to_signed_bytes_be();

        let shares = sham.split(&secret_bytes).unwrap();

        let recovered_secret12 = sham.recover(&shares[0..2]).unwrap();
        let recovered_secret23 = sham.recover(&shares[1..3]).unwrap();
        assert_eq!(secret_bytes, recovered_secret12);
        assert_eq!(secret_bytes, recovered_secret23);

        let shares31 = vec![shares[2].clone(), shares[0].clone()];
        let recovered_secret31 = sham.recover(&shares31.as_slice()).unwrap();
        assert_eq!(secret_bytes, recovered_secret31);
    }

    #[test]
    fn test_shamir3of5() {
        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 5,
        };

        let mut rng = rand::thread_rng();
        let secret: BigInt = rng.gen_bigint_range(&BigInt::from(1), &get_prime());
        let secret_bytes = secret.to_signed_bytes_be();

        let shares = sham.split(&secret_bytes).unwrap();

        let recovered_secret123 = sham.recover(&shares[0..3]).unwrap();
        let recovered_secret234 = sham.recover(&shares[1..4]).unwrap();
        let recovered_secret345 = sham.recover(&shares[2..5]).unwrap();
        assert_eq!(secret_bytes, recovered_secret123);
        assert_eq!(secret_bytes, recovered_secret234);
        assert_eq!(secret_bytes, recovered_secret345);

        let shares152 = vec![shares[0].clone(), shares[4].clone(), shares[1].clone()];
        let recovered_secret152 = sham.recover(&shares152.as_slice());
        assert_eq!(secret_bytes, recovered_secret152.unwrap());
    }

    #[test]
    fn test_shamir4of4() {
        let mut sham = SecretSharing {
            threshold: 4,
            numshares: 4,
        };

        let mut rng = rand::thread_rng();
        let secret: BigInt = rng.gen_bigint_range(&BigInt::from(1), &get_prime());
        let secret_bytes = secret.to_signed_bytes_be();

        let shares = sham.split(&secret_bytes).unwrap();

        let recovered_secret = sham.recover(&shares).unwrap();
        assert_eq!(secret_bytes, recovered_secret);

        let shares = vec![
            shares[0].clone(),
            shares[3].clone(),
            shares[2].clone(),
            shares[1].clone(),
        ];
        let recovered_secret_unordered = sham.recover(&shares.as_slice());
        assert_eq!(secret_bytes, recovered_secret_unordered.unwrap());
    }

    #[test]
    fn test_more_than_threshold() {
        let mut sham = SecretSharing {
            threshold: 2,
            numshares: 5,
        };

        let mut rng = rand::thread_rng();
        let secret: BigInt = rng.gen_bigint_range(&BigInt::from(1), &get_prime());
        let secret_bytes = secret.to_signed_bytes_be();

        let shares = sham.split(&secret_bytes).unwrap();

        let recovered_secret123 = sham.recover(&shares[0..3]).unwrap();
        let recovered_secret2345 = sham.recover(&shares[1..5]).unwrap();
        let recovered_secret_all = sham.recover(&shares).unwrap();
        assert_eq!(secret_bytes, recovered_secret123);
        assert_eq!(secret_bytes, recovered_secret2345);
        assert_eq!(secret_bytes, recovered_secret_all);

        let shares1524 = vec![
            shares[0].clone(),
            shares[4].clone(),
            shares[1].clone(),
            shares[3].clone(),
        ];
        let recovered_secret1524 = sham.recover(&shares1524.as_slice());
        assert_eq!(secret_bytes, recovered_secret1524.unwrap());
    }

    #[test]
    fn test_errors() {
        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 2,
        };

        let e = sham.split(&vec![1, 2]).unwrap_err();
        assert_eq!(e, Error::ThresholdGreaterThanNumShares);

        let mut sham = SecretSharing {
            threshold: 1,
            numshares: 1,
        };
        let e = sham.split(&vec![1, 2]).unwrap_err();
        assert_eq!(e, Error::MustSplitTrust);

        let mut sham = SecretSharing {
            threshold: 3,
            numshares: 5,
        };

        let mut rng = rand::thread_rng();
        let secret: BigInt = rng.gen_bigint_range(&BigInt::from(1), &get_prime());
        let secret_bytes = secret.to_signed_bytes_be();

        let shares = sham.split(&secret_bytes).unwrap();
        let e = sham.recover(&shares[0..2]).unwrap_err();
        assert_eq!(e, Error::BelowThreshold);

        let secret: BigInt = get_prime().clone();
        let e = sham.split(&secret.to_signed_bytes_be()).unwrap_err();
        assert_eq!(e, Error::SecretMustBeInRangePrime);

        let secret_bytes = BigInt::from(-10).to_signed_bytes_be();
        let e = sham.split(&secret_bytes).unwrap_err();
        assert_eq!(e, Error::SecretMustBeInRangePrime);
    }
}
