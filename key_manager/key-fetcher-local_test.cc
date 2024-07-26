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
ABSL_DECLARE_FLAG(std::string, secret);

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::testing::StrEq;

TEST(KeyFetcherLocal, Normal) {
  {
    absl::SetFlag(&FLAGS_primary_private_key, "key1-1");
    absl::SetFlag(&FLAGS_secondary_private_key, "key1-2");
    absl::SetFlag(&FLAGS_secret, "secret1");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
                IsOkAndHolds(StrEq("key1-1")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("key1-2")));
    EXPECT_THAT(key_fetcher->GetSecret(/*secret_id=*/""),
                IsOkAndHolds(StrEq("secret1")));
  }
  {
    absl::SetFlag(&FLAGS_primary_private_key, "key2-1");
    absl::SetFlag(&FLAGS_secondary_private_key, "key2-2");
    absl::SetFlag(&FLAGS_secret, "secret2");
    std::unique_ptr<KeyFetcher> key_fetcher = KeyFetcher::Create();
    EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
                IsOkAndHolds(StrEq("key2-1")));
    EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
                IsOkAndHolds(StrEq("key2-2")));
    EXPECT_THAT(key_fetcher->GetSecret(/*secret_id=*/""),
                IsOkAndHolds(StrEq("secret2")));
  }
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
