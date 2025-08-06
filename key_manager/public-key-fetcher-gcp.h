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

#ifndef HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_GCP_H_
#define HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_GCP_H_

#include <memory>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/public-key-fetcher.h"

namespace pcit::key_manager {

class PublicKeyFetcherGcp : public PublicKeyFetcher {
 public:
  PublicKeyFetcherGcp() = delete;
  // For unit-tests only.
  static std::unique_ptr<PublicKeyFetcher> Create(
      google::cloud::spanner::Client spanner_client);
  PublicKeyFetcherGcp(absl::string_view project_id,
                      absl::string_view instance_id,
                      absl::string_view database_id);
  // Fetch the last public keys for each user ordered by Secret
  // UpdateTimestamp.
  absl::StatusOr<std::vector<PerOriginPublicKey>> GetLatestPublicKeys()
      override;

 private:
  // For unit-tests only.
  explicit PublicKeyFetcherGcp(google::cloud::spanner::Client spanner_client);

  google::cloud::spanner::Client spanner_client_;
};

}  // namespace pcit::key_manager

#endif  // HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_GCP_H_
