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

#include "crypto/secret-data.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"

namespace privacy_sandbox::crypto {
namespace {

using ::testing::HasSubstr;
using ::testing::StrEq;

TEST(SecretData, Normal) {
  uint8_t* buffer;
  constexpr size_t kSize = 5;
  SecretData secret_data(kSize);
  ASSERT_THAT(secret_data.GetSize(), kSize);
  // Fill the buffer.
  for (size_t i = 0; i < secret_data.GetSize(); ++i) {
    secret_data.GetData()[i] = i + 0x61;
  }

  // Check string view.
  EXPECT_THAT(secret_data.GetStringView(), StrEq("abcde"));
  // Check array elements.
  for (size_t i = 0; i < secret_data.GetSize(); ++i) {
    EXPECT_THAT(secret_data.GetData()[i], i + 0x61);
  }
  buffer = secret_data.GetData();
  secret_data.Cleanse();
  // Make sure that the buffer is cleared.
  for (size_t i = 0; i < kSize; ++i) {
    EXPECT_THAT(buffer[i], 0x0);
  }
}

TEST(SecretData, Resize) {
  uint8_t* buffer;
  constexpr size_t kSize = 5;
  SecretData secret_data(kSize);
  ASSERT_THAT(secret_data.GetSize(), kSize);
  // Fill the buffer.
  for (size_t i = 0; i < secret_data.GetSize(); ++i) {
    secret_data.GetData()[i] = i + 0x61;
  }

  // Check string view.
  EXPECT_THAT(secret_data.GetStringView(), StrEq("abcde"));

  // Resize
  HATS_EXPECT_OK(secret_data.Resize(1));
  EXPECT_THAT(secret_data.GetStringView(), StrEq("a"));
  buffer = secret_data.GetData();
  secret_data.Cleanse();

  // Make sure that the whole buffer is cleared.
  for (size_t i = 0; i < kSize; ++i) {
    EXPECT_THAT(buffer[i], 0x0);
  }
}

TEST(SecretData, CreateFromStringView) {
  uint8_t* buffer;
  constexpr absl::string_view kSecretData = "very secret";
  SecretData secret_data(kSecretData);
  // Check string view.
  EXPECT_THAT(secret_data.GetStringView(), StrEq(kSecretData));
  buffer = secret_data.GetData();
  HATS_ASSERT_OK(secret_data.Resize(4));
  EXPECT_THAT(secret_data.GetStringView(), StrEq("very"));
  secret_data.Cleanse();
  // Make sure that the buffer is cleared.
  for (size_t i = 0; i < kSecretData.size(); ++i) {
    EXPECT_THAT(buffer[i], 0x0);
  }
}

TEST(SecretData, ResizeError) {
  constexpr size_t kSize = 5;
  SecretData secret_data(kSize);
  ASSERT_THAT(secret_data.GetSize(), kSize);
  HATS_EXPECT_STATUS_MESSAGE(secret_data.Resize(10),
                             absl::StatusCode::kInvalidArgument,
                             HasSubstr("Size increase is not supported."));
}

}  // namespace
}  // namespace privacy_sandbox::crypto
