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

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::crypto {
namespace {

using ::absl_testing::StatusIs;
using ::testing::HasSubstr;

// Silly randomness test, this is meant to catch situations if there is no
// randomness (i.e. bytes are hard coded).
TEST(RandomAeadKey, Rondomness) {
  SecretData key1 = RandomAeadKey();
  SecretData key2 = RandomAeadKey();
  ASSERT_EQ(key1.GetSize(), 32);
  ASSERT_EQ(key2.GetSize(), 32);
  EXPECT_NE(key1.GetStringView(), key2.GetStringView());
}

// Test that encrypted data can be decrypted.
TEST(EncryptDecrypt, Normal) {
  SecretData key = RandomAeadKey();
  SecretData data("secret_data");
  absl::StatusOr<std::string> encrypted_data = Encrypt(key, data, "hats");
  EXPECT_TRUE(encrypted_data.ok());
  EXPECT_NE(data.GetStringView(), *encrypted_data);
  absl::StatusOr<SecretData> plaintext =
      Decrypt(key, SecretData(*encrypted_data), "hats");
  EXPECT_TRUE(plaintext.ok());
  EXPECT_EQ(data.GetStringView(), plaintext->GetStringView());
}

// Test that `Encrypt` return different ciphertext for the same plaintext.
TEST(Encrypt, Normal) {
  SecretData key = RandomAeadKey();
  SecretData data("secret_data");
  absl::StatusOr<std::string> encrypted_data1 = Encrypt(key, data, "hats");
  EXPECT_TRUE(encrypted_data1.ok());
  absl::StatusOr<std::string> encrypted_data2 = Encrypt(key, data, "hats");
  EXPECT_TRUE(encrypted_data2.ok());
  EXPECT_NE(*encrypted_data1, *encrypted_data2);
}

TEST(Encrypt, Error) {
  SecretData key(1);
  SecretData data("secret_data");
  EXPECT_THAT(Encrypt(key, data, "hats"),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("EVP_AEAD_CTX_init failed")));
}

TEST(Decrypt, Error) {
  {
    SecretData key(1);
    SecretData data("secret_data");
    EXPECT_THAT(Decrypt(key, data, "hats"),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("The object must be larger than 15")));
  }
  {
    SecretData key = RandomAeadKey();
    SecretData data("secret_data");
    absl::StatusOr<std::string> encrypted_data = Encrypt(key, data, "tag1");
    ASSERT_TRUE(encrypted_data.ok());
    EXPECT_THAT(Decrypt(key, SecretData(*encrypted_data), "tag2"),
                StatusIs(absl::StatusCode::kFailedPrecondition,
                         HasSubstr("EVP_AEAD_CTX_open failed")));
  }
}

}  // namespace
}  // namespace privacy_sandbox::crypto
