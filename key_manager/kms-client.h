// Copyright 2024 Google LLC.
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

#ifndef HATS_KEY_MANAGER_KMS_CLIENT_H
#define HATS_KEY_MANAGER_KMS_CLIENT_H

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "key_manager/kms-client.h"

// Defines an interface for interacting with a Key Management System (KMS)
// service.  This abstraction allows for the implementation to be swapped
// out with minimal code changes.  For example, the implementation could
// use the Google Cloud Platform KMS, or it could use a local KMS for
// testing purposes.
namespace privacy_sandbox::key_manager {
enum class ProtectionLevel { SOFTWARE, HSM, UNKNOWN };

enum class CryptoKeyPurpose { ASYMMETRIC_SIGN, ENCRYPT_DECRYPT };

struct PublicKey {
  std::string pem_key;
  ProtectionLevel protection_level;
};

struct CryptoKey {
  std::string key_id;
  CryptoKeyPurpose purpose;
};

class KmsClient {
 public:
  virtual ~KmsClient() = default;

  virtual absl::StatusOr<PublicKey> GetPublicKey(std::string const& key_id) = 0;

  virtual absl::StatusOr<CryptoKey> CreateAsymmetricKey(
      std::string const& parent, std::string const& key_id) = 0;

  virtual absl::StatusOr<std::string> EncryptData(
      std::string const& key_id, std::string const& plaintext) = 0;

  virtual absl::StatusOr<std::string> DecryptData(
      std::string const& key_id, std::string const& ciphertext) = 0;
};

}  // namespace privacy_sandbox::key_manager
#endif  // HATS_KEY_MANAGER_KMS_CLIENT
