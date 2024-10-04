/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HATS_CRYPTO_EC_KEY_H_
#define HATS_CRYPTO_EC_KEY_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "openssl/ec_key.h"

namespace privacy_sandbox::crypto {

// Helper class to generate and wrap EC keys.
class EcKey final {
 public:
  EcKey(const EcKey&) = delete;
  EcKey(EcKey&&) = default;
  EcKey& operator=(const EcKey&) = delete;
  EcKey& operator=(EcKey&&) = default;

  static absl::StatusOr<std::unique_ptr<EcKey>> Create();

  ~EcKey();

  // Get the EC private key in bytes format.
  absl::StatusOr<SecretData> GetPrivateKey() const;

  // Wrap the EC private key with an AEAD key.
  absl::StatusOr<std::string> WrapPrivateKey(
      const SecretData& wrapping_key, absl::string_view associated_data) const;

  absl::StatusOr<std::string> GetPublicKey() const;

  absl::StatusOr<std::string> GetPublicKeyInHex() const;

 private:
  EcKey(EC_KEY* ec_key);

  EC_KEY* ec_key_;
};

}  // namespace privacy_sandbox::crypto

#endif  // HATS_CRYPTO_EC_KEY_H_
