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

#ifndef HATS_CRYPTO_AEAD_CRYPTER_H_
#define HATS_CRYPTO_AEAD_CRYPTER_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"

namespace pcit::crypto {

// Predefined associated data for secrets used by the TVS.
constexpr absl::string_view kTvsPrivateKeyAd = "hats_tvs_private_key";
constexpr absl::string_view kSecretAd = "hats_secret";

// Generate a random AES 256 key.
SecretData RandomAeadKey();

// Encrypt a message using AES-256 in GCM mode.
absl::StatusOr<std::string> Encrypt(const SecretData& key,
                                    const SecretData& plaintext,
                                    absl::string_view associated_data);

// Decrypt a message using AES-256 in GCM mode.
absl::StatusOr<SecretData> Decrypt(const SecretData& key,
                                   const SecretData& ciphertext,
                                   absl::string_view associated_data);

}  // namespace pcit::crypto

#endif  // HATS_CRYPTO_AEAD_CRYPTER_H_
