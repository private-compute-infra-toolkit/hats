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

#ifndef PRIVACY_SANDBOX_CLIENT_CRYPTO_HPKE_CRYPTER_H_
#define PRIVACY_SANDBOX_CLIENT_CRYPTO_HPKE_CRYPTER_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "openssl/hpke.h"

namespace privacy_sandbox::crypto {

constexpr absl::string_view kSecretHpkeAd = "hats_secret";

struct HpkeKeyPair {
  SecretData private_key;
  std::string public_key;
};

// Generates a new HPKE key pair.
absl::StatusOr<HpkeKeyPair> GenerateHpkeKeyPair();

// Encrypts a message using HPKE.
absl::StatusOr<std::string> HpkeEncrypt(absl::string_view public_key,
                                        const SecretData& plaintext,
                                        absl::string_view associated_data);

// Decrypts a message using HPKE.
absl::StatusOr<SecretData> HpkeDecrypt(const SecretData& private_key,
                                       const SecretData& ciphertext,
                                       absl::string_view associated_data);

}  // namespace privacy_sandbox::crypto

#endif  // PRIVACY_SANDBOX_CLIENT_CRYPTO_HPKE_CRYPTER_H_
