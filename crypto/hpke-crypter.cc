// Copyright 2025 Google LLC.
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

#include "crypto/hpke-crypter.h"

#include <iostream>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "crypto/secret-data.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hpke.h"
#include "openssl/rand.h"

namespace pcit::crypto {

absl::StatusOr<HpkeKeyPair> GenerateHpkeKeyPair() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, /*e=*/nullptr);
  EVP_PKEY* privkey = nullptr;
  auto cleanup = [pctx, privkey] {
    // EVP_PKEY_CTX_free checks for null-ness before freeing.
    EVP_PKEY_CTX_free(pctx);
    // EVP_PKEY_free checks for null-ness before freeing.
    EVP_PKEY_free(privkey);
  };
  if (pctx == nullptr) {
    cleanup();
    return absl::InternalError("Error generating private key context.");
  }
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    cleanup();
    return absl::InternalError("Error initializing private key context.");
  }
  if (EVP_PKEY_keygen(pctx, &privkey) <= 0) {
    cleanup();
    return absl::InternalError("Error generating private key.");
  }

  size_t pubkey_len;
  if (EVP_PKEY_get_raw_public_key(privkey, /*e=*/nullptr, &pubkey_len) <= 0) {
    cleanup();
    return absl::InternalError("Error getting public key length.");
  }
  std::vector<unsigned char> pubkey(pubkey_len);
  if (EVP_PKEY_get_raw_public_key(privkey, pubkey.data(), &pubkey_len) <= 0) {
    cleanup();
    return absl::InternalError("Error getting public key.");
  }
  size_t raw_priv_len;
  if (EVP_PKEY_get_raw_private_key(privkey, /*e=*/nullptr, &raw_priv_len) <=
      0) {
    cleanup();
    return absl::InternalError("Error getting raw private key length.");
  }
  std::vector<uint8_t> raw_priv(raw_priv_len);
  if (EVP_PKEY_get_raw_private_key(privkey, raw_priv.data(), &raw_priv_len) <=
      0) {
    cleanup();
    return absl::InternalError("Error getting raw private key.");
  }
  SecretData priv_key_sd(absl::string_view(
      reinterpret_cast<const char*>(raw_priv.data()), raw_priv_len));
  std::string pub_key_sd =
      std::string(reinterpret_cast<const char*>(pubkey.data()), pubkey_len);
  cleanup();
  return HpkeKeyPair{priv_key_sd, pub_key_sd};
}

absl::StatusOr<std::string> HpkeEncrypt(absl::string_view public_key,
                                        const SecretData& plaintext,
                                        absl::string_view associated_data) {
  const EVP_HPKE_KEM* kem = EVP_hpke_x25519_hkdf_sha256();
  const EVP_HPKE_AEAD* aead = EVP_hpke_aes_256_gcm();
  const EVP_HPKE_KDF* kdf = EVP_hpke_hkdf_sha256();
  std::vector<unsigned char> enc(EVP_HPKE_KEM_enc_len(kem));
  std::vector<unsigned char> info(associated_data.begin(),
                                  associated_data.end());
  std::vector<unsigned char> pt(plaintext.GetStringView().begin(),
                                plaintext.GetStringView().end());
  size_t enc_len, ct_len;

  EVP_HPKE_CTX* ctx = EVP_HPKE_CTX_new();
  if (!ctx) {
    return absl::InternalError("Error creating HPKE context.");
  }
  auto cleanup = [ctx] {
    // EVP_HPKE_CTX_free checks for null-ness before freeing.
    EVP_HPKE_CTX_free(ctx);
  };

  if (!EVP_HPKE_CTX_setup_sender(
          ctx, enc.data(), &enc_len, enc.size(), kem, kdf, aead,
          reinterpret_cast<const uint8_t*>(public_key.data()),
          public_key.size(), info.data(), info.size())) {
    cleanup();
    return absl::InvalidArgumentError("Error setting up sender context.");
  }

  std::vector<unsigned char> ciphertext(pt.size() +
                                        EVP_HPKE_CTX_max_overhead(ctx));

  if (!EVP_HPKE_CTX_seal(ctx, ciphertext.data(), &ct_len, ciphertext.size(),
                         pt.data(), pt.size(), /*e=*/nullptr, 0)) {
    cleanup();
    return absl::InternalError("Error in EVP_HPKE_CTX_seal.");
  }
  cleanup();

  enc.resize(enc_len);
  ciphertext.resize(ct_len);
  return absl::StrCat(
      absl::string_view(reinterpret_cast<char*>(enc.data()), enc_len),
      absl::string_view(reinterpret_cast<char*>(ciphertext.data()), ct_len));
}

absl::StatusOr<SecretData> HpkeDecrypt(const SecretData& private_key,
                                       const SecretData& ciphertext,
                                       absl::string_view associated_data) {
  const EVP_HPKE_KEM* kem = EVP_hpke_x25519_hkdf_sha256();
  const EVP_HPKE_AEAD* aead = EVP_hpke_aes_256_gcm();
  const EVP_HPKE_KDF* kdf = EVP_hpke_hkdf_sha256();
  EVP_HPKE_CTX* ctx = EVP_HPKE_CTX_new();
  EVP_HPKE_KEY* hpke_key = EVP_HPKE_KEY_new();
  auto cleanup = [ctx, hpke_key] {
    // EVP_HPKE_CTX_free checks for null-ness before freeing.
    EVP_HPKE_CTX_free(ctx);
    // EVP_HPKE_KEY_free checks for null-ness before freeing.
    EVP_HPKE_KEY_free(hpke_key);
  };
  if (!hpke_key) {
    cleanup();
    return absl::InternalError("Error creating EVP_HPKE_KEY.");
  }
  if (!ctx) {
    cleanup();
    return absl::InternalError("Error creating HPKE context for decryption.");
  }
  size_t enc_len = EVP_HPKE_KEM_enc_len(kem);
  std::vector<unsigned char> info(associated_data.begin(),
                                  associated_data.end());
  if (ciphertext.GetSize() <= enc_len) {
    cleanup();
    return absl::InvalidArgumentError("Invalid ciphertext");
  }
  absl::string_view enc_str = ciphertext.GetStringView().substr(0, enc_len);
  std::vector<unsigned char> enc(enc_str.begin(), enc_str.end());
  absl::string_view ct_str = ciphertext.GetStringView().substr(enc_len);
  std::vector<unsigned char> ct(ct_str.begin(), ct_str.end());
  if (!EVP_HPKE_KEY_init(hpke_key, kem, private_key.GetData(),
                         private_key.GetSize())) {
    cleanup();
    return absl::InternalError("Error initializing EVP_HPKE_KEY.");
  }

  if (!EVP_HPKE_CTX_setup_recipient(ctx, hpke_key, kdf, aead, enc.data(),
                                    enc.size(), info.data(), info.size())) {
    cleanup();
    return absl::InternalError("Error setting up recipient context.");
  }

  std::vector<unsigned char> recovered_plaintext(ciphertext.GetSize());
  size_t recovered_pt_len;
  if (!EVP_HPKE_CTX_open(ctx, recovered_plaintext.data(), &recovered_pt_len,
                         recovered_plaintext.size(), ct.data(), ct.size(),
                         /*e=*/nullptr, 0)) {
    cleanup();
    return absl::InternalError(
        "Error in EVP_HPKE_CTX_open (decryption failed!).");
  }
  cleanup();

  recovered_plaintext.resize(recovered_pt_len);
  return SecretData(absl::string_view(
      reinterpret_cast<char*>(recovered_plaintext.data()), recovered_pt_len));
}

}  // namespace pcit::crypto
