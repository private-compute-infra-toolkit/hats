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

#include "key_manager/key-fetcher-gcp.h"

#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::StrEq;

class TestKeyManagementServiceConnection
    : public google::cloud::kms_v1::v2_25::KeyManagementServiceConnection {
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
  Decrypt(const google::cloud::kms::v1::DecryptRequest& request) override {
    google::cloud::kms::v1::DecryptResponse response;
    if (request.name() ==
        "projects/test-project/locations/location1/keyRings/keyring1/"
        "cryptoKeys/key1") {
      response.set_plaintext("primary_key");
    } else if (request.name() ==
               "projects/test-project/locations/location1/keyRings/keyring1/"
               "cryptoKeys/secret1") {
      response.set_plaintext("secret");
    }
    return response;
  }
};

TEST(KeyFetcherGcp, Normal) {
  absl::SetFlag(&FLAGS_project_id, "test-project");
  absl::SetFlag(&FLAGS_location_id, "location1");
  absl::SetFlag(&FLAGS_key_ring_id, "keyring1");
  absl::SetFlag(&FLAGS_private_key_id, "key1");
  absl::SetFlag(&FLAGS_secret_id, "secret1");
  absl::SetFlag(&FLAGS_secret, "030201");
  absl::SetFlag(&FLAGS_primary_private_key, "010203");
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client));
  EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
              IsOkAndHolds(StrEq("primary_key")));
  EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
              StatusIs(absl::StatusCode::kUnimplemented));
  EXPECT_THAT(key_fetcher->GetSecret(/*secret_id=*/""),
              IsOkAndHolds(StrEq("secret")));
}

TEST(KeyFetcherGcp, Error) {
  absl::SetFlag(&FLAGS_project_id, "test-project");
  absl::SetFlag(&FLAGS_location_id, "location1");
  absl::SetFlag(&FLAGS_key_ring_id, "keyring1");
  absl::SetFlag(&FLAGS_private_key_id, "key1");
  absl::SetFlag(&FLAGS_secret_id, "secret1");
  absl::SetFlag(&FLAGS_secret, "secret");
  absl::SetFlag(&FLAGS_primary_private_key, "private_key");
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client));
  EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse primary private key")));
  EXPECT_THAT(key_fetcher->GetSecret(/*secret_id=*/""),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse secret ke")));
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
