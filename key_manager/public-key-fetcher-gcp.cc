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

#include "key_manager/public-key-fetcher-gcp.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gcp_common/flags.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/public-key-fetcher.h"
#include "status_macro/status_macros.h"

namespace privacy_sandbox::key_manager {

PublicKeyFetcherGcp::PublicKeyFetcherGcp(
    google::cloud::spanner::Client spanner_client)
    : spanner_client_(std::move(spanner_client)) {}
PublicKeyFetcherGcp::PublicKeyFetcherGcp(absl::string_view project_id,
                                         absl::string_view instance_id,
                                         absl::string_view database_id)
    : spanner_client_(google::cloud::spanner::MakeConnection(
          google::cloud::spanner::Database(std::string(project_id),
                                           std::string(instance_id),
                                           std::string(database_id)))) {}
absl::StatusOr<std::vector<PerOriginPublicKey>>
PublicKeyFetcherGcp::GetLatestPublicKeys() {
  // We do the subquery because of poor ARRAY_AGG implementation in Cloud
  // Spanner:
  // 1. ARRAY_AGG doesn't support ORDER BY UpdateTimestamp LIMIT 1.
  // 2. ARRAY_AGG(STRUCT(p.SecretId, p.PublicKey) HAVING MAX UpdateTimestamp) is
  // also not supported with nullable struct error.
  auto rows =
      spanner_client_.ExecuteQuery(google::cloud::spanner::SqlStatement(R"sql(
SELECT p.SecretId, p.PublicKey, u.Origin
FROM
(
SELECT MAX(s.UpdateTimestamp) AS max_update_timestamp, u.Origin
FROM Secrets AS s, Users AS u
WHERE u.UserId = s.UserId
GROUP BY u.Origin
) AS ts,
Secrets AS s,
UserPublicKeys AS p,
Users AS u
WHERE s.SecretId=p.SecretId
  AND s.UpdateTimestamp=ts.max_update_timestamp
  AND u.Origin=ts.Origin
    )sql"));

  using RowType = std::tuple<int64_t, std::string, std::string>;
  std::vector<PerOriginPublicKey> keys;
  for (const auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    PerOriginPublicKey key{.key_id = std::get<0>(*row),
                           .public_key = std::get<1>(*row),
                           .origin = std::get<2>(*row)};
    // Check for duplication just in case that two keys having exactly the
    // same update timestamp and origins.
    bool already_exist = false;
    for (const PerOriginPublicKey& existing_key : keys) {
      if (existing_key.origin == key.origin) {
        already_exist = true;
        break;
      }
    }
    if (!already_exist) keys.push_back(std::move(key));
  }

  return keys;
}

std::unique_ptr<PublicKeyFetcher> PublicKeyFetcherGcp::Create(
    google::cloud::spanner::Client spanner_client) {
  // The constructor is private so we use WrapUnique.
  return absl::WrapUnique(new PublicKeyFetcherGcp(std::move(spanner_client)));
}

std::unique_ptr<PublicKeyFetcher> PublicKeyFetcher::Create() {
  return std::make_unique<PublicKeyFetcherGcp>(
      absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_instance_id),
      absl::GetFlag(FLAGS_database_id));
}
}  // namespace privacy_sandbox::key_manager
