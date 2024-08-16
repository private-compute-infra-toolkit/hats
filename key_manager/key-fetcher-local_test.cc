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
ABSL_DECLARE_FLAG(std::string, secret_public_key);
ABSL_DECLARE_FLAG(std::string, secret);

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

TEST(KeyFetcherLocal, Normal) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "6669727374");
    absl::SetFlag(&FLAGS_secondary_private_key, "7365636f6e64");
    absl::SetFlag(&FLAGS_user_key_id, 500);
    absl::SetFlag(&FLAGS_secret_public_key, "73656372657431-public");
    absl::SetFlag(&FLAGS_secret, "73656372657431");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
                IsOkAndHolds(StrEq("first")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("second")));
    EXPECT_THAT(key_fetcher->GetSecrets(/*username=*/""),
                IsOkAndHolds(UnorderedElementsAre(
                    FieldsAre(500, "73656372657431-public", "secret1"))));
  }
  {
    absl::SetFlag(&FLAGS_primary_private_key, "61");
    absl::SetFlag(&FLAGS_secondary_private_key, "62");
    absl::SetFlag(&FLAGS_user_key_id, 501);
    absl::SetFlag(&FLAGS_secret_public_key, "73656372657432-public");
    absl::SetFlag(&FLAGS_secret, "73656372657432");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(), IsOkAndHolds(StrEq("a")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("b")));
    EXPECT_THAT(key_fetcher->GetSecrets(/*username=*/""),
                IsOkAndHolds(UnorderedElementsAre(
                    FieldsAre(501, "73656372657432-public", "secret2"))));
  }
}

TEST(KeyFetcherLocal, Error) {
  absl::SetFlag(&FLAGS_primary_private_key, "zz");
  absl::SetFlag(&FLAGS_secondary_private_key, "xx");
  std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
  EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse the primary private key")));
  EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse the secondary private key")));
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
