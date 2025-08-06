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

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "gcp_common/flags.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/sql_statement.h"
#include "google/cloud/spanner/transaction.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher-gcp-common-utils.h"
#include "key_manager/key-fetcher.h"
#include "status_macro/status_macros.h"

namespace pcit::key_manager {

namespace {

// Maximum number of secrets to return to the user.
constexpr int64_t kMaxSecrets = 2;

absl::StatusOr<std::vector<Keys>> WrappedSecretsByUserIdFromSpanner(
    int64_t user_id, google::cloud::spanner::Client& client) {
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          ResourceName, Dek, Secrets.SecretId, PublicKey, Secret
      FROM
          Secrets, DataEncryptionKeys, KeyEncryptionKeys, UserPublicKeys
      WHERE
          KeyEncryptionKeys.KekId = DataEncryptionKeys.KekId
          AND Secrets.DekId = DataEncryptionKeys.DekId
          AND Secrets.SecretId = UserPublicKeys.SecretId
          AND Secrets.UserId = @user_id
      ORDER BY UpdateTimestamp DESC
      LIMIT @limit)sql",
      {{"user_id", google::cloud::spanner::Value(user_id)},
       {"limit", google::cloud::spanner::Value(kMaxSecrets)}});
  using RowType =
      std::tuple<std::string, google::cloud::spanner::Bytes, int64_t,
                 std::string, google::cloud::spanner::Bytes>;
  auto rows = client.ExecuteQuery(std::move(select));
  std::vector<Keys> keys;
  for (auto row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    keys.push_back({
        .kek = std::get<0>(*row),
        .dek = std::get<1>(*row).get<std::string>(),
        .key_id = std::get<2>(*row),
        .public_key = std::get<3>(*row),
        .private_key = std::get<4>(*row).get<std::string>(),
    });
  }
  if (keys.empty()) {
    return absl::NotFoundError("Cannot find secret for the user.");
  }
  return keys;
}

}  // namespace

KeyFetcherGcp::KeyFetcherGcp(
    google::cloud::kms_v1::v2_36::KeyManagementServiceClient gcp_kms_client,
    google::cloud::spanner::Client spanner_client)
    : gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          std::move(gcp_kms_client))),
      spanner_client_(std::move(spanner_client)) {}

KeyFetcherGcp::KeyFetcherGcp(absl::string_view project_id,
                             absl::string_view instance_id,
                             absl::string_view database_id)
    : gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection())),
      spanner_client_(google::cloud::spanner::MakeConnection(
          google::cloud::spanner::Database(std::string(project_id),
                                           std::string(instance_id),
                                           std::string(database_id)))) {}

absl::StatusOr<std::string> KeyFetcherGcp::GetPrimaryPrivateKey() {
  HATS_ASSIGN_OR_RETURN(
      Keys keys, WrappedEcKeyFromSpanner("primary_key", spanner_client_));
  HATS_ASSIGN_OR_RETURN(
      crypto::SecretData secret_data,
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, keys));
  return std::string(secret_data.GetStringView());
}

absl::StatusOr<std::string> KeyFetcherGcp::GetSecondaryPrivateKey() {
  HATS_ASSIGN_OR_RETURN(
      Keys keys, WrappedEcKeyFromSpanner("secondary_key", spanner_client_));
  HATS_ASSIGN_OR_RETURN(
      crypto::SecretData secret_data,
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, keys));
  return std::string(secret_data.GetStringView());
}

absl::StatusOr<std::string> KeyFetcherGcp::UserIdForAuthenticationKey(
    absl::string_view public_key) {
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          UserId
      FROM
          UserAuthenticationKeys
      WHERE
          PublicKey = @public_key)sql",
      {{"public_key", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(public_key))}});
  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row :
       google::cloud::spanner::StreamOf<std::tuple<int64_t>>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    return std::to_string(std::get<0>(*row));
  }
  return absl::NotFoundError("Cannot find user");
}

absl::StatusOr<std::vector<Secret>> KeyFetcherGcp::GetSecretsForUserId(
    absl::string_view user_id) {
  int64_t user_id_int64;
  if (!absl::SimpleAtoi(user_id, &user_id_int64)) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid user ID: '%s'. Failed to convert user ID to Integer.",
        user_id));
  }
  HATS_ASSIGN_OR_RETURN(
      std::vector<Keys> keys,
      WrappedSecretsByUserIdFromSpanner(user_id_int64, spanner_client_));

  std::vector<Secret> secrets;
  // Use non-const to enable effective use of std::move().
  for (Keys& key : keys) {
    HATS_ASSIGN_OR_RETURN(
        crypto::SecretData secret_data,
        UnwrapSecret(crypto::kSecretAd, gcp_kms_client_, key));
    secrets.push_back({
        .key_id = std::to_string(key.key_id),
        .public_key = std::move(key.public_key),
        .private_key = std::string(secret_data.GetStringView()),
    });
  }
  return secrets;
}

absl::StatusOr<bool> KeyFetcherGcp::MaybeAcquireLock(
    absl::string_view user_id) {
  bool lock_acquired = false;
  int64_t user_id_int64;
  if (!absl::SimpleAtoi(user_id, &user_id_int64)) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid user ID: '%s'. Failed to convert user ID to Integer.",
        user_id));
  }
  auto commit = spanner_client_.Commit(
      [&spanner_client_ = spanner_client_, &user_id_int64,
       &lock_acquired](google::cloud::spanner::Transaction transaction)
          -> google::cloud::StatusOr<google::cloud::spanner::Mutations> {
        google::cloud::spanner::SqlStatement select(
            R"sql(
              SELECT
                  LockExpiryTime
              FROM
                  Users
              WHERE
                  Users.UserId = @user_id)sql",
            {{"user_id", google::cloud::spanner::Value(user_id_int64)}});
        auto query = spanner_client_.ExecuteQuery(std::move(transaction),
                                                  std::move(select));

        auto row = google::cloud::spanner::GetSingularRow(
            google::cloud::spanner::StreamOf<std::tuple<int64_t>>(query));
        int64_t lockExpiryTime = std::get<0>(*row);
        int64_t currentTime = absl::ToUnixSeconds(absl::Now());

        if (lockExpiryTime < currentTime) {
          google::cloud::spanner::SqlStatement update(
              R"sql(
                  UPDATE
                      Users
                  SET
                      Users.LockExpiryTime = TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 20 MINUTE)
                  WHERE
                      Users.UserId = @user_id)sql",
              {{"user_id", google::cloud::spanner::Value(user_id_int64)}});
          HATS_ASSIGN_OR_RETURN(
              auto _, spanner_client_.ExecuteDml(transaction, update));
          lock_acquired = true;
        }
        return google::cloud::spanner::Mutations{};  // Indicate success
      });
  HATS_RETURN_IF_ERROR(commit.status());
  return lock_acquired;
}

std::unique_ptr<KeyFetcher> KeyFetcherGcp::Create(
    google::cloud::kms_v1::v2_36::KeyManagementServiceClient gcp_kms_client,
    google::cloud::spanner::Client spanner_client) {
  // The constructor is private so we use WrapUnique.
  return absl::WrapUnique(
      new KeyFetcherGcp(std::move(gcp_kms_client), std::move(spanner_client)));
}

std::unique_ptr<KeyFetcher> KeyFetcher::Create() {
  return std::make_unique<KeyFetcherGcp>(absl::GetFlag(FLAGS_project_id),
                                         absl::GetFlag(FLAGS_instance_id),
                                         absl::GetFlag(FLAGS_database_id));
}

}  // namespace pcit::key_manager
