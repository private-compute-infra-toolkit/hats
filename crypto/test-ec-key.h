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

#ifndef HATS_CRYPTO_TEST_EC_KEY_H_
#define HATS_CRYPTO_TEST_EC_KEY_H_

#include <string>

#include "absl/status/statusor.h"
#include "crypto/secret-data.h"

namespace pcit::crypto {
struct TestEcKey {
  std::string private_key_hex;
  crypto::SecretData private_key;
  std::string public_key;
  std::string public_key_hex;
};

// Create an ECKey pair for unit-tests.
// The function extract the public and private key and reduce error handling in
// unit-tests.
absl::StatusOr<TestEcKey> GenerateEcKeyForTest();

}  // namespace pcit::crypto

#endif  // HATS_CRYPTO_TEST_EC_KEY_H_
