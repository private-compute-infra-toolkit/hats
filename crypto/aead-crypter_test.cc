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
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"

namespace privacy_sandbox::crypto {
namespace {

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
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                            Encrypt(key, data, "hats"));
  EXPECT_NE(data.GetStringView(), encrypted_data);
  HATS_ASSERT_OK_AND_ASSIGN(SecretData plaintext,
                            Decrypt(key, SecretData(encrypted_data), "hats"));
  EXPECT_EQ(data.GetStringView(), plaintext.GetStringView());
}

// Test that `Encrypt` return different ciphertext for the same plaintext.
TEST(Encrypt, Normal) {
  SecretData key = RandomAeadKey();
  SecretData data("secret_data");
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data1,
                            Encrypt(key, data, "hats"));
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data2,
                            Encrypt(key, data, "hats"));
  EXPECT_NE(encrypted_data1, encrypted_data2);
}

TEST(Encrypt, Error) {
  SecretData key(1);
  SecretData data("secret_data");
  HATS_EXPECT_STATUS_MESSAGE(Encrypt(key, data, "hats"),
                             absl::StatusCode::kFailedPrecondition,
                             HasSubstr("EVP_AEAD_CTX_init failed"));
}

TEST(Decrypt, Error) {
  {
    SecretData key(1);
    SecretData data("secret_data");
    HATS_EXPECT_STATUS_MESSAGE(Decrypt(key, data, "hats"),
                               absl::StatusCode::kInvalidArgument,
                               HasSubstr("The object must be larger than 15"));
  }
  {
    SecretData key = RandomAeadKey();
    SecretData data("secret_data");
    HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                              Encrypt(key, data, "tag1"));
    HATS_EXPECT_STATUS_MESSAGE(Decrypt(key, SecretData(encrypted_data), "tag2"),
                               absl::StatusCode::kFailedPrecondition,
                               HasSubstr("EVP_AEAD_CTX_open failed"));
  }
}

}  // namespace
}  // namespace privacy_sandbox::crypto
