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

#include "crypto/test-ec-key.h"

#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "crypto/ec-key.h"
#include "crypto/secret-data.h"
#include "status_macro/status_macros.h"

namespace pcit::crypto {

absl::StatusOr<TestEcKey> GenerateEcKeyForTest() {
  HATS_ASSIGN_OR_RETURN(std::unique_ptr<crypto::EcKey> ec_key,
                        crypto::EcKey::Create());

  HATS_ASSIGN_OR_RETURN(crypto::SecretData private_key,
                        ec_key->GetPrivateKey());

  HATS_ASSIGN_OR_RETURN(std::string public_key, ec_key->GetPublicKey());

  HATS_ASSIGN_OR_RETURN(std::string public_key_hex,
                        ec_key->GetPublicKeyInHex());
  return TestEcKey{
      .private_key_hex = absl::BytesToHexString(private_key.GetStringView()),
      .private_key = std::move(private_key),
      .public_key = std::move(public_key),
      .public_key_hex = std::move(public_key_hex),
  };
}

}  // namespace pcit::crypto
