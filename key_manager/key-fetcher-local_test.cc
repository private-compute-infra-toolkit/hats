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

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/status/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "key_manager/key-fetcher.h"

ABSL_DECLARE_FLAG(std::string, primary_private_key);
ABSL_DECLARE_FLAG(std::string, secondary_private_key);
ABSL_DECLARE_FLAG(int64_t, user_key_id);
ABSL_DECLARE_FLAG(std::string, user_public_key);
ABSL_DECLARE_FLAG(std::string, user_secret);
ABSL_DECLARE_FLAG(std::string, user_authentication_public_key);

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

TEST(KeyFetcherLocal, Normal) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "6669727374");
    absl::SetFlag(&FLAGS_secondary_private_key, "7365636f6e64");
    absl::SetFlag(&FLAGS_user_key_id, 500);
    absl::SetFlag(&FLAGS_user_public_key, "73656372657431-public");
    absl::SetFlag(&FLAGS_user_secret, "73656372657431");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "41424344");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
                IsOkAndHolds(StrEq("first")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("second")));
    EXPECT_THAT(key_fetcher->GetSecretsForUserId(/*user_id=*/1),
                IsOkAndHolds(UnorderedElementsAre(
                    FieldsAre(500, "73656372657431-public", "secret1"))));
    EXPECT_THAT(key_fetcher->UserIdForAuthenticationKey("ABCD"),
                IsOkAndHolds(Eq(1)));
  }
  {
    absl::SetFlag(&FLAGS_primary_private_key, "61");
    absl::SetFlag(&FLAGS_secondary_private_key, "62");
    absl::SetFlag(&FLAGS_user_key_id, 501);
    absl::SetFlag(&FLAGS_user_public_key, "73656372657432-public");
    absl::SetFlag(&FLAGS_user_secret, "73656372657432");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "5a44454647");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(), IsOkAndHolds(StrEq("a")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("b")));
    EXPECT_THAT(key_fetcher->GetSecretsForUserId(/*user_id=*/1),
                IsOkAndHolds(UnorderedElementsAre(
                    FieldsAre(501, "73656372657432-public", "secret2"))));
    EXPECT_THAT(key_fetcher->UserIdForAuthenticationKey("ZDEFG"),
                IsOkAndHolds(Eq(1)));
  }
}

TEST(KeyFetcherLocal, Error) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "zz");
    absl::SetFlag(&FLAGS_secondary_private_key, "xx");
    absl::SetFlag(&FLAGS_user_secret, "zz");
    absl::SetFlag(&FLAGS_user_authentication_public_key, "zz");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("Failed to parse the primary private key")));
    EXPECT_THAT(
        key_fetcher->GetSecondaryPrivateKey(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Failed to parse the secondary private key")));
    EXPECT_THAT(key_fetcher->GetSecretsForUserId(/*user_id=*/1),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("Failed to parse the secret")));
    EXPECT_THAT(
        key_fetcher->UserIdForAuthenticationKey("ZDEFG"),
        StatusIs(
            absl::StatusCode::kInvalidArgument,
            HasSubstr("Failed to parse the user authentication public key")));
  }
  {
    absl::SetFlag(&FLAGS_user_authentication_public_key, "5a44454647");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetSecretsForUserId(/*user_id=*/500),
                StatusIs(absl::StatusCode::kNotFound,
                         HasSubstr("Cannot find user id '500'")));
    EXPECT_THAT(key_fetcher->UserIdForAuthenticationKey("ABCD"),
                StatusIs(absl::StatusCode::kUnauthenticated,
                         HasSubstr("unregistered or expired public key")));
  }
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
