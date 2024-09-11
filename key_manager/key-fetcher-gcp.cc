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
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "gcp_common/flags.h"
#include "gcp_common/gcp-status.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher.h"

namespace privacy_sandbox::key_manager {

namespace {

constexpr absl::string_view kAssociatedData = "HATS_SECRET";

struct Keys {
  std::string kek;
  std::string dek;
  int64_t key_id;
  std::string public_key;
  std::string private_key;
};

absl::StatusOr<Keys> WrappedEcKeyFromSpanner(
    absl::string_view key_name, google::cloud::spanner::Client& client) {
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          ResourceName, Dek, PrivateKey
      FROM
          TVSPrivateKeys, DataEncryptionKeys, KeyEncryptionKeys
      WHERE
          KeyEncryptionKeys.KekId = DataEncryptionKeys.KekId
          AND TVSPrivateKeys.DekId = DataEncryptionKeys.DekId
          AND TVSPrivateKeys.KeyId = @key_name)sql",
      {{"key_name", google::cloud::spanner::Value(std::string(key_name))}});
  using RowType = std::tuple<std::string, google::cloud::spanner::Bytes,
                             google::cloud::spanner::Bytes>;
  auto rows = client.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    if (!row.ok()) {
      return gcp_common::GcpToAbslStatus(row.status());
    }
    return Keys{
        .kek = std::get<0>(*row),
        .dek = std::get<1>(*row).get<std::string>(),
        .private_key = std::get<2>(*row).get<std::string>(),
    };
  }
  return absl::NotFoundError(absl::StrCat("Cannot find '", key_name, "'"));
}

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
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    if (!row.ok()) {
      return gcp_common::GcpToAbslStatus(row.status());
    }
    keys.push_back({
        .kek = std::get<0>(*row),
        .dek = std::get<1>(*row).get<std::string>(),
        .key_id = std::get<2>(*row),
        .public_key = std::get<3>(*row),
        .private_key = std::get<4>(*row).get<std::string>(),
    });
  }
  if (keys.empty()) {
    return absl::NotFoundError(
        absl::StrCat("Cannot find secret for user '", user_id, "'"));
  }
  return keys;
}

absl::StatusOr<crypto::SecretData> UnwrapSecret(
    absl::string_view associated_data,
    privacy_sandbox::key_manager::GcpKmsClient& gcp_kms_client,
    const Keys& keys) {
  absl::StatusOr<std::string> unwrapped_dek =
      gcp_kms_client.DecryptData(keys.kek, keys.dek, kAssociatedData);
  if (!unwrapped_dek.ok()) {
    return unwrapped_dek.status();
  }
  return crypto::Decrypt(crypto::SecretData(*unwrapped_dek),
                         crypto::SecretData(keys.private_key), associated_data);
}

}  // namespace

KeyFetcherGcp::KeyFetcherGcp(
    google::cloud::kms_v1::v2_29::KeyManagementServiceClient gcp_kms_client,
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
  absl::StatusOr<Keys> keys =
      WrappedEcKeyFromSpanner("primary_key", spanner_client_);
  if (!keys.ok()) return keys.status();
  absl::StatusOr<crypto::SecretData> secret_data =
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, *keys);
  if (!secret_data.ok()) {
    return secret_data.status();
  }
  return std::string(secret_data->GetStringView());
}

absl::StatusOr<std::string> KeyFetcherGcp::GetSecondaryPrivateKey() {
  absl::StatusOr<Keys> keys =
      WrappedEcKeyFromSpanner("secondary_key", spanner_client_);
  if (!keys.ok()) return keys.status();
  absl::StatusOr<crypto::SecretData> secret_data =
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, *keys);
  if (!secret_data.ok()) {
    return secret_data.status();
  }
  return std::string(secret_data->GetStringView());
}

absl::StatusOr<int64_t> KeyFetcherGcp::UserIdForAuthenticationKey(
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
    if (!row.ok()) {
      return gcp_common::GcpToAbslStatus(row.status());
    }
    return std::get<0>(*row);
  }
  return absl::NotFoundError("Cannot find user");
}

absl::StatusOr<std::vector<Secret>> KeyFetcherGcp::GetSecretsForUserId(
    int64_t user_id) {
  absl::StatusOr<std::vector<Keys>> keys =
      WrappedSecretsByUserIdFromSpanner(user_id, spanner_client_);
  if (!keys.ok()) return keys.status();

  std::vector<Secret> secrets;
  // Use non-const to enable effective use of std::move().
  for (Keys& key : *keys) {
    absl::StatusOr<crypto::SecretData> secret_data =
        UnwrapSecret(crypto::kSecretAd, gcp_kms_client_, key);
    if (!secret_data.ok()) {
      return secret_data.status();
    }
    secrets.push_back({
        .key_id = key.key_id,
        .public_key = std::move(key.public_key),
        .private_key = std::string(secret_data->GetStringView()),
    });
  }
  return secrets;
}

std::unique_ptr<KeyFetcher> KeyFetcherGcp::Create(
    google::cloud::kms_v1::v2_29::KeyManagementServiceClient gcp_kms_client,
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

}  // namespace privacy_sandbox::key_manager
