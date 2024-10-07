/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto/aead-crypter.h"

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "crypto/secret-data.h"
#include "openssl/aead.h"
#include "openssl/rand.h"
#include "status_macro/status_macros.h"

namespace privacy_sandbox::crypto {

namespace {

constexpr size_t kNonceSize = 15;
std::vector<uint8_t> RandomNonce() {
  std::vector<uint8_t> nonce(kNonceSize);
  RAND_bytes(nonce.data(), nonce.size());
  return nonce;
}

}  // namespace

constexpr size_t kKeySize = 32;
SecretData RandomAeadKey() {
  SecretData key(kKeySize);
  RAND_bytes(key.GetData(), key.GetSize());
  return key;
}

absl::StatusOr<std::string> Encrypt(const SecretData& key,
                                    const SecretData& plaintext,
                                    absl::string_view associated_data) {
  std::vector<uint8_t> nonce = RandomNonce();
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_256_gcm(), key.GetData(),
                         key.GetSize(), EVP_AEAD_DEFAULT_TAG_LENGTH,
                         /*impl=*/nullptr)) {
    return absl::FailedPreconditionError("EVP_AEAD_CTX_init failed.");
  }

  std::vector<uint8_t> ciphertext(EVP_AEAD_MAX_OVERHEAD + plaintext.GetSize());
  size_t ciphertext_len;
  std::vector<uint8_t> associated_data_bytes(associated_data.begin(),
                                             associated_data.end());
  if (!EVP_AEAD_CTX_seal(
          ctx.get(), ciphertext.data(), &ciphertext_len, ciphertext.size(),
          nonce.data(), nonce.size(), plaintext.GetData(), plaintext.GetSize(),
          associated_data_bytes.data(), associated_data_bytes.size())) {
    return absl::FailedPreconditionError("EVP_AEAD_CTX_seal failed.");
  }

  // Resize the vector to the actual cipher length.
  ciphertext.resize(ciphertext_len);
  // Return the nonce and ciphertext (ciphertext already includes the tag).
  // The format of the returned vector is as follows:
  // |nonce|cipher|tag|.
  return std::string(nonce.begin(), nonce.end()) +
         std::string(ciphertext.begin(), ciphertext.end());
}

absl::StatusOr<SecretData> Decrypt(const SecretData& key,
                                   const SecretData& ciphertext,
                                   absl::string_view associated_data) {
  if (ciphertext.GetSize() < kNonceSize + 1) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Ciphertext size '", ciphertext.GetSize(),
        "' is too small. The object must be larger than ", kNonceSize,
        " as it should contain the nonce, ciphertext and tag."));
  }
  const uint8_t* nonce = ciphertext.GetData();
  const uint8_t* cipher_tag = ciphertext.GetData() + kNonceSize;
  size_t cipher_tag_len = ciphertext.GetSize() - kNonceSize;

  std::vector<uint8_t> associated_data_bytes(associated_data.begin(),
                                             associated_data.end());
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_256_gcm(), key.GetData(),
                         key.GetSize(), EVP_AEAD_DEFAULT_TAG_LENGTH,
                         /*impl=*/nullptr)) {
    return absl::FailedPreconditionError("EVP_AEAD_CTX_init failed.");
  }
  // Plaintext size is equal or smaller than the ciphertext.
  SecretData plaintext(ciphertext.GetSize());
  size_t plaintext_size = 0;

  if (!EVP_AEAD_CTX_open(ctx.get(), plaintext.GetData(), &plaintext_size,
                         plaintext.GetSize(), nonce, kNonceSize, cipher_tag,
                         cipher_tag_len, associated_data_bytes.data(),
                         associated_data_bytes.size())) {
    return absl::FailedPreconditionError("EVP_AEAD_CTX_open failed.");
  }
  // Resize to the actual plaintext size.
  HATS_RETURN_IF_ERROR(plaintext.Resize(plaintext_size));
  return plaintext;
}

}  // namespace privacy_sandbox::crypto
