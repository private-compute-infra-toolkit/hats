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

#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"

namespace privacy_sandbox::crypto {
namespace {

// Silly randomness test, this is meant to catch situations if there is no
// randomness (i.e. bytes are hard coded).
TEST(EcKey, Randomness) {
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<EcKey> ec_key1, EcKey::Create());
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<EcKey> ec_key2, EcKey::Create());

  HATS_ASSERT_OK_AND_ASSIGN(SecretData private_key1, ec_key1->GetPrivateKey());
  HATS_ASSERT_OK_AND_ASSIGN(SecretData private_key2, ec_key2->GetPrivateKey());
  EXPECT_NE(private_key1.GetStringView(), private_key2.GetStringView());
}

TEST(EcKey, WrapPrivateKey) {
  {
    HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<EcKey> ec_key, EcKey::Create());
    HATS_ASSERT_OK_AND_ASSIGN(SecretData ec_private_key,
                              ec_key->GetPrivateKey());

    SecretData wrapping_key = RandomAeadKey();
    HATS_ASSERT_OK_AND_ASSIGN(
        std::string wrapped_ec_private_key,
        ec_key->WrapPrivateKey(wrapping_key, "hats_test1"));

    // Unwrap the key and check if it was encrypted with the correct parameters.
    HATS_ASSERT_OK_AND_ASSIGN(
        SecretData data,
        Decrypt(wrapping_key, SecretData(wrapped_ec_private_key),
                "hats_test1"));
    EXPECT_EQ(ec_private_key.GetStringView(), data.GetStringView());
  }
  {
    HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<EcKey> ec_key, EcKey::Create());
    HATS_ASSERT_OK_AND_ASSIGN(SecretData ec_private_key,
                              ec_key->GetPrivateKey());

    SecretData wrapping_key = RandomAeadKey();
    HATS_ASSERT_OK_AND_ASSIGN(
        std::string wrapped_ec_private_key,
        ec_key->WrapPrivateKey(wrapping_key, "hats_test2"));

    // Unwrap the key and check if it was encrypted with the correct parameters.
    HATS_ASSERT_OK_AND_ASSIGN(
        SecretData data,
        Decrypt(wrapping_key, SecretData(wrapped_ec_private_key),
                "hats_test2"));
    EXPECT_EQ(ec_private_key.GetStringView(), data.GetStringView());
  }
}

}  // namespace
}  // namespace privacy_sandbox::crypto
