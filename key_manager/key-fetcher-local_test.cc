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

#include <memory>
#include <string>

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "key_manager/key-fetcher.h"
#include "status_macro/status_test_macros.h"

ABSL_DECLARE_FLAG(std::string, primary_private_key);
ABSL_DECLARE_FLAG(std::string, secondary_private_key);
ABSL_DECLARE_FLAG(std::string, user_key_id);
ABSL_DECLARE_FLAG(std::string, user_public_key);
ABSL_DECLARE_FLAG(std::string, user_secret);
ABSL_DECLARE_FLAG(std::string, user_authentication_public_key);

namespace pcit::key_manager {
namespace {

using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

TEST(KeyFetcherLocal, Normal) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "6669727374");
    absl::SetFlag(&FLAGS_secondary_private_key, "7365636f6e64");
    absl::SetFlag(&FLAGS_user_key_id, "500");
    absl::SetFlag(&FLAGS_user_public_key, "73656372657431-public");
    absl::SetFlag(&FLAGS_user_secret, "73656372657431");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "41424344");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetPrimaryPrivateKey(),
                             StrEq("first"));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetSecondaryPrivateKey(),
                             StrEq("second"));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetSecretsForUserId(/*user_id=*/"1"),
                             UnorderedElementsAre(FieldsAre(
                                 "500", "73656372657431-public", "secret1")));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->UserIdForAuthenticationKey("ABCD"),
                             Eq("1"));
  }
  {
    absl::SetFlag(&FLAGS_primary_private_key, "61");
    absl::SetFlag(&FLAGS_secondary_private_key, "62");
    absl::SetFlag(&FLAGS_user_key_id, "501");
    absl::SetFlag(&FLAGS_user_public_key, "73656372657432-public");
    absl::SetFlag(&FLAGS_user_secret, "73656372657432");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "5a44454647");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetPrimaryPrivateKey(), StrEq("a"));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetSecondaryPrivateKey(), StrEq("b"));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetSecretsForUserId(/*user_id=*/"1"),
                             UnorderedElementsAre(FieldsAre(
                                 "501", "73656372657432-public", "secret2")));
    HATS_EXPECT_OK_AND_HOLDS(key_fetcher->UserIdForAuthenticationKey("ZDEFG"),
                             Eq("1"));
  }
}

TEST(KeyFetcherLocal, Error) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "zz");
    absl::SetFlag(&FLAGS_secondary_private_key, "xx");
    absl::SetFlag(&FLAGS_user_secret, "zz");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "zz");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    HATS_EXPECT_STATUS_MESSAGE(
        key_fetcher->GetPrimaryPrivateKey(), absl::StatusCode::kInvalidArgument,
        HasSubstr("Failed to parse the primary private key"));
    HATS_EXPECT_STATUS_MESSAGE(
        key_fetcher->GetSecondaryPrivateKey(),
        absl::StatusCode::kInvalidArgument,
        HasSubstr("Failed to parse the secondary private key"));
    HATS_EXPECT_STATUS_MESSAGE(
        key_fetcher->GetSecretsForUserId(/*user_id=*/"1"),
        absl::StatusCode::kInvalidArgument,
        HasSubstr("Failed to parse the secret"));
    HATS_EXPECT_STATUS_MESSAGE(
        key_fetcher->UserIdForAuthenticationKey("ZDEFG"),

        absl::StatusCode::kInvalidArgument,
        HasSubstr("Failed to parse the user authentication public key"));
  }
  {
    absl::SetFlag(&FLAGS_user_authentication_public_key, "5a44454647");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    HATS_EXPECT_STATUS_MESSAGE(
        key_fetcher->GetSecretsForUserId(/*user_id=*/"500"),
        absl::StatusCode::kNotFound,
        HasSubstr("Cannot find secret for the user"));
    HATS_EXPECT_STATUS_MESSAGE(key_fetcher->UserIdForAuthenticationKey("ABCD"),
                               absl::StatusCode::kUnauthenticated,
                               HasSubstr("unregistered or expired public key"));
  }
}

}  // namespace

}  // namespace pcit::key_manager
