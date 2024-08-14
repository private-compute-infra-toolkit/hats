// Copyright 2024 Oak Authors
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

#![feature(generic_const_exprs)]

extern crate alloc;
extern crate std;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
pub const NONCE_LEN: usize = 12;
pub const SHA1_OUTPUT_LEN: usize = 20;
pub const SHA256_OUTPUT_LEN: usize = 32;
pub const HASHLEN: usize = 32;
pub const SYMMETRIC_KEY_LEN: usize = 32;

/// The length of an uncompressed, X9.62 encoding of a P-256 point.
pub const P256_X962_LENGTH: usize = 65;

/// The length of a P-256 scalar value.
pub const P256_SCALAR_LENGTH: usize = 32;

#[derive(Error, Debug)]
pub enum AeadError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

#[derive(Error, Debug)]
pub enum DigestError {
    #[error("Hash computation failed")]
    HashComputationFailed,
    #[error("HKDF derivation failed")]
    HkdfDerivationFailed,
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
}

#[derive(Error, Debug)]
pub enum HpkeError {
    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Key encapsulation failed")]
    EncapsulationFailed,

    #[error("Key decapsulation failed")]
    DecapsulationFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("HKDF key derivation failed")]
    HkdfDerivationFailed,

    #[error("AEAD context setup failed")]
    AeadContextSetupFailed,
}

// Defines CrypoProvider Core trait to be implemented by
// BoringSSL, RustCrypto, and Ring instances
pub enum CryptoProviderType {
    RustCrypto,
    Ring,
    BoringSSL,
}
pub trait CryptoProvider {
    fn provider_type(&self) -> CryptoProviderType;
}

pub struct OakCiphersuite {
    pub hpke: &'static dyn Hpke,
    pub hdfk: &'static dyn Hkdf,
    pub aead: &'static dyn Aead,
    pub digest: &'static dyn Digest,
    pub signature: &'static dyn Signature,
}
pub enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
}

pub trait Aead {
    fn seal_in_place(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    );

    fn open_in_place(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AeadError>;
}

pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

pub trait Rand {
    fn rand_bytes(&mut self, output: &mut [u8]);
}

pub trait P256Scalar {
    /// Generates a new P-256 scalar
    fn generate() -> Self
    where
        Self: Sized;

    /// Computes the public key corresponding to this scalar
    fn compute_public_key(&self) -> [u8; P256_X962_LENGTH];

    /// Returns the bytes representation of this scalar
    fn bytes(&self) -> [u8; P256_SCALAR_LENGTH];
}

pub trait Hmac {
    // Computes the HMAC-SHA-256 message authentication code.s
    fn hmac_sha256(&mut self, key: &[u8], msg: &[u8]) -> [u8; SHA256_OUTPUT_LEN];

    // Applies HMAC using the hash function
    fn hmac_hash(&mut self, key: &[u8], data: &[u8]) -> Vec<u8>;
}

// Trait definitions for RSA and EDCSA key pairs
pub trait Signature {
    /// Creates an key pair from a PKCS#8 encoded key
    fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, SignatureError>
    where
        Self: Sized;

    /// Generates a new key pair and returns the PKCS#8 encoded private key
    fn generate_pkcs8() -> Result<Self, SignatureError>
    where
        Self: Sized;

    /// Returns the public key of the key pair
    fn public_key(&self) -> Result<Vec<u8>, SignatureError>;

    /// Signs the provided data using the key pair
    fn sign(&self, signed_data: &[u8]) -> Result<Vec<u8>, SignatureError>;

    /// Verifies the provided data using the public key and the signature
    fn verify(&self, pub_key: &[u8], signed_data: &[u8], signature: &[u8]) -> bool;
}

pub trait Kem {
    type PublicKey;
    type PrivateKey;
    type EncapsulatedKey;

    fn encapsulate(&self, pk: &Self::PublicKey) -> (Self::EncapsulatedKey, Vec<u8>);
    fn decapsulate(
        &self,
        sk: &Self::PrivateKey,
        encapsulated_key: &Self::EncapsulatedKey,
    ) -> Vec<u8>;
}

pub trait Hkdf {
    // HKDF key derivation function.
    fn hkdf(
        &self,
        chaining_key: &[u8],
        ikm: &[u8],
        num_outputs: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>), ()>;

    // Computes the HKDF-SHA-256 key derivation function.
    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), DigestError>;

    // Returns pseudorandom key from initial keying material.
    fn hkdf_extract(&self, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8>;

    // Returns output keying material from pseudorandom key.
    fn hkdf_expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, ()>;
}

pub struct OpModeR<'a> {
    pub mode: &'a str,
}

pub struct OpModeS<'a> {
    pub mode: &'a str,
}
pub trait HpkeSetupSender<R>
where
    R: CryptoRng + RngCore,
{
    fn setup_sender(
        &self,
        mode: &OpModeS<'_>,
        pk_recip: &[u8],
        info: &[u8],
        csprng: &mut R,
    ) -> Result<(Vec<u8>, AeadCtxS), HpkeError>;
}

pub trait Hpke {
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);

    fn create_receiver_context(
        &self,
        mode: &OpModeR<'_>,
        sk_recip: &[u8],
        encapped_key: &[u8],
        info: &[u8],
    ) -> Result<AeadCtxR, HpkeError>;
}

pub struct AeadCtxS {
    pub key: Vec<u8>,         // The key used for encryption
    pub nonce: Vec<u8>,       // The nonce used for encryption
    pub aad: Option<Vec<u8>>, // Optional associated data
}

pub struct AeadCtxR {
    pub key: Vec<u8>,         // The key used for encryption
    pub nonce: Vec<u8>,       // The nonce used for encryption
    pub aad: Option<Vec<u8>>, // Optional associated data
}

pub trait DiffieHellmanX25519 {
    const DHLEN: usize = 32;

    /// Generates a new Curve25519 key pair.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
    fn handshake_hash(&self, keypair: (&[u8; Self::DHLEN], &[u8]), public_key: &[u8]) -> Vec<u8>;
}

pub trait DiffieHellmanCurve448 {
    const DHLEN: usize = 56;

    /// Generates a new Curve448 key pair.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);

    /// Executes the Curve448 Diffie-Hellman function.
    /// Returns the shared secret as a `Vec<u8>`.
    fn handshake_hash(&self, keypair: &[u8; Self::DHLEN], public_key: &[u8]) -> Vec<u8>;
}

pub trait DiffieHellmanP256Scalar {
    const DHLEN: usize = 32;

    /// Generates a new P-266 key pair.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);

    /// Executes the P-256 Diffie-Hellman function.
    /// Takes a private key and a public key to compute the shared secret.
    fn handshake_hash(&self, private_key: &[u8; Self::DHLEN], public_key: &[u8]) -> Vec<u8>;
}
