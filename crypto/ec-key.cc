// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "crypto/ec-key.h"

#include <memory>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "openssl/bn.h"
#include "openssl/nid.h"

namespace privacy_sandbox::crypto {

EcKey::EcKey(EC_KEY* ec_key) : ec_key_(ec_key) {}

EcKey::~EcKey() { EC_KEY_free(ec_key_); }

absl::StatusOr<std::unique_ptr<EcKey>> EcKey::Create() {
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ec_key == nullptr) {
    return absl::InternalError("EC_KEY_new_by_curve_name() failed");
  }
  if (EC_KEY_generate_key(ec_key) != 1) {
    return absl::InternalError("EC Key generation failed");
  }
  return absl::WrapUnique(new EcKey(ec_key));
}

absl::StatusOr<SecretData> EcKey::GetPrivateKey() const {
  const BIGNUM* private_key_bn = EC_KEY_get0_private_key(ec_key_);
  SecretData private_key(32);
  if (!BN_bn2binpad(private_key_bn, private_key.GetData(),
                    private_key.GetSize())) {
    return absl::InternalError("BN_bn2binpad() failed");
  }
  return private_key;
}

// Wrap the EC private key with an AEAD key.
absl::StatusOr<std::string> EcKey::WrapPrivateKey(
    const SecretData& wrapping_key, absl::string_view associated_data) const {
  absl::StatusOr<SecretData> private_key = GetPrivateKey();
  if (!private_key.ok()) return private_key.status();

  return privacy_sandbox::crypto::Encrypt(wrapping_key, *private_key,
                                          associated_data);
}

absl::StatusOr<std::string> EcKey::GetPublicKey() const {
  const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key_);
  const EC_GROUP* key_group = EC_KEY_get0_group(ec_key_);
  std::vector<uint8_t> key_data(65);
  size_t length =
      EC_POINT_point2oct(key_group, public_key, POINT_CONVERSION_UNCOMPRESSED,
                         reinterpret_cast<uint8_t*>(key_data.data()),
                         key_data.size(), /*ctx=*/nullptr);
  if (length != key_data.size()) {
    return absl::InternalError("EC_POINT_point2oct() failed.");
  }
  return std::string(key_data.begin(), key_data.end());
}

absl::StatusOr<std::string> EcKey::GetPublicKeyInHex() const {
  absl::StatusOr<std::string> public_key = GetPublicKey();
  if (!public_key.ok()) return public_key.status();
  return absl::BytesToHexString(*public_key);
}

}  // namespace privacy_sandbox::crypto
