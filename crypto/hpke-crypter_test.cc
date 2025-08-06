/*
 * Copyright 2025 Google LLC
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

#include "crypto/hpke-crypter.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"

namespace pcit::crypto {
namespace {

using ::testing::HasSubstr;

// Test that encrypted data can be decrypted.
TEST(EncryptDecrypt, Normal) {
  HATS_ASSERT_OK_AND_ASSIGN(HpkeKeyPair keypair1, GenerateHpkeKeyPair());
  SecretData data("secret_data");
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                            HpkeEncrypt(keypair1.public_key, data, "hats"));
  EXPECT_NE(data.GetStringView(), encrypted_data);
  HATS_ASSERT_OK_AND_ASSIGN(
      SecretData plaintext,
      HpkeDecrypt(keypair1.private_key, SecretData(encrypted_data), "hats"));
  EXPECT_EQ(data.GetStringView(), plaintext.GetStringView());
}

// Test that `Encrypt` return different ciphertext for the same plaintext.
TEST(Encrypt, Normal) {
  HATS_ASSERT_OK_AND_ASSIGN(HpkeKeyPair keypair1, GenerateHpkeKeyPair());
  SecretData data("secret_data");
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data1,
                            HpkeEncrypt(keypair1.public_key, data, "hats"));
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data2,
                            HpkeEncrypt(keypair1.public_key, data, "hats"));
  EXPECT_NE(encrypted_data1, encrypted_data2);
}

TEST(Encrypt, Error) {
  absl::string_view key("pub_key");
  SecretData data("secret_data");
  HATS_EXPECT_STATUS_MESSAGE(HpkeEncrypt(key, data, "hats"),
                             absl::StatusCode::kInvalidArgument,
                             HasSubstr("Error setting up sender context."));
}

TEST(Decrypt, Error) {
  {
    SecretData key("1");
    SecretData data("secret_data");
    HATS_EXPECT_STATUS_MESSAGE(HpkeDecrypt(key, data, "hats"),
                               absl::StatusCode::kInvalidArgument,
                               HasSubstr("Invalid ciphertext"));
  }
  {
    HATS_ASSERT_OK_AND_ASSIGN(HpkeKeyPair keypair1, GenerateHpkeKeyPair());
    SecretData data("secret_data");
    HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                              HpkeEncrypt(keypair1.public_key, data, "tag1"));
    HATS_EXPECT_STATUS_MESSAGE(
        HpkeDecrypt(keypair1.private_key, SecretData(encrypted_data), "tag2"),
        absl::StatusCode::kInternal,
        HasSubstr("Error in EVP_HPKE_CTX_open (decryption failed!)"));
  }
}

}  // namespace
}  // namespace pcit::crypto
