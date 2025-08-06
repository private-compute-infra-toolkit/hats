// Copyright 2025 Google LLC.
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

#include "key_manager/key-fetcher-gcp-coordinator.h"

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/marshalling.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "crypto/secret_sharing/src/interface.rs.h"
#include "gcp_common/flags.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/sql_statement.h"
#include "google/cloud/spanner/transaction.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher-gcp-common-utils.h"
#include "key_manager/key-fetcher.h"
#include "status_macro/status_macros.h"
#include "tvs/telemetry/otel-counter.h"

struct CoordinatorVersion {
  explicit CoordinatorVersion(int v = 1) : version(v) {}

  int version;  // Valid range is [1..2]
};

// Returns a textual flag value corresponding to the CoordinatorVersion `v`.
std::string AbslUnparseFlag(CoordinatorVersion v) {
  // Delegate to the usual unparsing for int.
  return absl::UnparseFlag(v.version);
}

// Parses a CoordinatorVersion from the command line flag value `text`.
// Returns true and sets `*v` on success; returns false and sets `*error`
// on failure.
bool AbslParseFlag(absl::string_view text, CoordinatorVersion* v,
                   std::string* error) {
  // Convert from text to int using the int-flag parser.
  if (!absl::ParseFlag(text, &v->version, error)) {
    return false;
  }
  if (v->version < 1 || v->version > 2) {
    *error = "not in range [1,2]";
    return false;
  }
  return true;
}

ABSL_FLAG(std::string, coordinator_project_id, "",
          "Coordinator GCP Project ID.");
ABSL_FLAG(std::string, coordinator_instance_id, "",
          "Coordinator Spanner instance ID.");
ABSL_FLAG(std::string, coordinator_database_id, "",
          "Coordinator Spanner database ID.");
ABSL_FLAG(int64_t, max_age_seconds, 3888000,
          "Max age of keys to fetch from Spanner.");
ABSL_FLAG(CoordinatorVersion, coordinator_version, CoordinatorVersion(1),
          "Major version of coordinator");

namespace pcit::key_manager {

namespace {

constexpr absl::string_view kAuthKeyCounterName =
    "origin_for_authentication_key";
constexpr absl::string_view kAuthKeyCounterHelp =
    "Number of requests to UserIdForAuthenticationKey for an "
    "authentication key.";
constexpr absl::string_view kAuthKeyCounterUnit = "requests";

// The keyUri returned from KeyVendingService contains prefix "gcp-kms://" or
// "aws-kms://", and we need to remove it before sending for decryption.
constexpr int kKeyArnPrefixSize = 10;

absl::StatusOr<std::vector<Secret>> WrappedSecretsByUserIdFromSpanner(
    absl::string_view user_id, google::cloud::spanner::Client& client,
    pcit::key_manager::GcpKmsClient& gcp_kms_client, int64_t max_age_seconds,
    int64_t coordinator_version) {
  google::cloud::spanner::SqlStatement select;
  if (coordinator_version == 1) {
    select = google::cloud::spanner::SqlStatement(
        R"sql(
      SELECT
          KeyId, PublicKeyMaterial, PrivateKey, KeyEncryptionKeyUri
      FROM
          KeySets
      WHERE
          CreatedAt >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @max_age_seconds SECOND)
      ORDER BY ExpiryTime DESC, ActivationTime DESC)sql",
        {{"max_age_seconds", google::cloud::spanner::Value(max_age_seconds)}});
  } else {
    return absl::UnimplementedError("unimplemented");
  }

  using RowType =
      std::tuple<std::string, std::string, std::string, std::string>;
  auto rows = client.ExecuteQuery(std::move(select));
  std::vector<Secret> secrets;
  for (auto row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    std::string unescaped_wrapped_key;
    if (!absl::Base64Unescape(std::get<2>(*row), &unescaped_wrapped_key)) {
      return absl::NotFoundError("Failed to decode secrets for the user.");
    }
    HATS_ASSIGN_OR_RETURN(std::string unwrapped_private_key,
                          gcp_kms_client.DecryptData(
                              std::get<3>(*row).substr(kKeyArnPrefixSize),
                              unescaped_wrapped_key, /*associated_data=*/""));

    // Wrap the private key into a TVS serialized XOR Share struct.
    HATS_ASSIGN_OR_RETURN(
        rust::Vec<rust::String> shares,
        pcit::crypto::XorSplitSecret(rust::Slice<const std::uint8_t>(
                                         reinterpret_cast<const unsigned char*>(
                                             unwrapped_private_key.data()),
                                         unwrapped_private_key.size()),
                                     1),
        _.PrependWith("Failed to serialize XOR secret: "));
    secrets.push_back({.key_id = std::get<0>(*row),
                       .public_key = std::get<1>(*row),
                       .private_key = static_cast<std::string>(shares[0])});
  }
  if (secrets.empty()) {
    return absl::NotFoundError("Cannot find secret for the user.");
  }
  return secrets;
}

}  // namespace

KeyFetcherGcpCoordinator::KeyFetcherGcpCoordinator(
    google::cloud::kms_v1::v2_36::KeyManagementServiceClient gcp_kms_client,
    google::cloud::spanner::Client tvs_spanner_client,
    google::cloud::spanner::Client coordinator_spanner_client,
    int64_t max_age_seconds, int64_t coordinator_version)
    : gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          std::move(gcp_kms_client))),
      tvs_spanner_client_(std::move(tvs_spanner_client)),
      coordinator_spanner_client_(std::move(coordinator_spanner_client)),
      max_age_seconds_(max_age_seconds),
      coordinator_version_(coordinator_version),
      origin_for_authentication_key_counter_(pcit::tvs::OtelCounter(
          kAuthKeyCounterName, kAuthKeyCounterHelp, kAuthKeyCounterUnit)) {}

KeyFetcherGcpCoordinator::KeyFetcherGcpCoordinator(
    absl::string_view tvs_project_id, absl::string_view tvs_instance_id,
    absl::string_view tvs_database_id, absl::string_view coordinator_project_id,
    absl::string_view coordinator_instance_id,
    absl::string_view coordinator_database_id, int64_t max_age_seconds,
    int64_t coordinator_version)
    : gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection())),
      tvs_spanner_client_(google::cloud::spanner::MakeConnection(
          google::cloud::spanner::Database(std::string(tvs_project_id),
                                           std::string(tvs_instance_id),
                                           std::string(tvs_database_id)))),
      coordinator_spanner_client_(google::cloud::spanner::MakeConnection(
          google::cloud::spanner::Database(
              std::string(coordinator_project_id),
              std::string(coordinator_instance_id),
              std::string(coordinator_database_id)))),
      max_age_seconds_(max_age_seconds),
      coordinator_version_(coordinator_version),
      origin_for_authentication_key_counter_(pcit::tvs::OtelCounter(
          kAuthKeyCounterName, kAuthKeyCounterHelp, kAuthKeyCounterUnit)) {}

absl::StatusOr<std::string> KeyFetcherGcpCoordinator::GetPrimaryPrivateKey() {
  HATS_ASSIGN_OR_RETURN(
      Keys keys, WrappedEcKeyFromSpanner("primary_key", tvs_spanner_client_));
  HATS_ASSIGN_OR_RETURN(
      crypto::SecretData secret_data,
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, keys));
  return std::string(secret_data.GetStringView());
}

absl::StatusOr<std::string> KeyFetcherGcpCoordinator::GetSecondaryPrivateKey() {
  HATS_ASSIGN_OR_RETURN(
      Keys keys, WrappedEcKeyFromSpanner("secondary_key", tvs_spanner_client_));
  HATS_ASSIGN_OR_RETURN(
      crypto::SecretData secret_data,
      UnwrapSecret(crypto::kTvsPrivateKeyAd, gcp_kms_client_, keys));
  return std::string(secret_data.GetStringView());
}

absl::StatusOr<std::string>
KeyFetcherGcpCoordinator::UserIdForAuthenticationKey(
    absl::string_view public_key) {
  // This metric has potentially high cardinality for a large number of unique
  // origins, consider disabling/transforming the export of this metric to
  // reduce cardinality in this case.
  origin_for_authentication_key_counter_.Increment(
      {{"authentication_key", absl::BytesToHexString(public_key)}});
  if (coordinator_version_ == 1) {
    // V1 coordinator does not support auth keys per user/origin. Allow all
    // users.
    return "";
  } else if (coordinator_version_ == 2) {
    google::cloud::spanner::SqlStatement select(
        R"sql(
      SELECT
          Origin
      FROM
          OriginPublicKeyAuthorizations
      WHERE
          ClientAuthPublicKey = @public_key)sql",
        {{"public_key",
          google::cloud::spanner::Value(std::string(public_key))}});
    auto rows = coordinator_spanner_client_.ExecuteQuery(std::move(select));
    for (auto& row :
         google::cloud::spanner::StreamOf<std::tuple<std::string>>(rows)) {
      HATS_RETURN_IF_ERROR(row.status());
      return std::get<0>(*row);
    }
    return absl::NotFoundError("Cannot find user");
  }
  return absl::UnimplementedError("unimplemented");
}

absl::StatusOr<std::vector<Secret>>
KeyFetcherGcpCoordinator::GetSecretsForUserId(absl::string_view user_id) {
  HATS_ASSIGN_OR_RETURN(
      std::vector<Secret> secrets,
      WrappedSecretsByUserIdFromSpanner(user_id, coordinator_spanner_client_,
                                        gcp_kms_client_, max_age_seconds_,
                                        coordinator_version_));
  return secrets;
}

absl::StatusOr<bool> KeyFetcherGcpCoordinator::MaybeAcquireLock(
    absl::string_view user_id) {
  return absl::UnimplementedError("unimplemented");
}

std::unique_ptr<KeyFetcher> KeyFetcherGcpCoordinator::Create(
    google::cloud::kms_v1::v2_36::KeyManagementServiceClient gcp_kms_client,
    google::cloud::spanner::Client tvs_spanner_client,
    google::cloud::spanner::Client coordinator_spanner_client,
    int64_t max_age_seconds, int64_t coordinator_version) {
  // The constructor is private so we use WrapUnique.
  return absl::WrapUnique(new KeyFetcherGcpCoordinator(
      std::move(gcp_kms_client), std::move(tvs_spanner_client),
      std::move(coordinator_spanner_client), max_age_seconds,
      coordinator_version));
}

std::unique_ptr<KeyFetcher> KeyFetcher::Create() {
  return std::make_unique<KeyFetcherGcpCoordinator>(
      absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_instance_id),
      absl::GetFlag(FLAGS_database_id),
      absl::GetFlag(FLAGS_coordinator_project_id),
      absl::GetFlag(FLAGS_coordinator_instance_id),
      absl::GetFlag(FLAGS_coordinator_database_id),
      absl::GetFlag(FLAGS_max_age_seconds),
      absl::GetFlag(FLAGS_coordinator_version).version);
}

}  // namespace pcit::key_manager
