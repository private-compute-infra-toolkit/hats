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

#include "key_manager/key-fetcher-gcp-common-utils.h"

#include <string>
#include <tuple>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/sql_statement.h"
#include "key_manager/gcp-kms-client.h"
#include "status_macro/status_macros.h"

namespace privacy_sandbox::key_manager {

constexpr absl::string_view kAssociatedData = "HATS_SECRET";

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
    HATS_RETURN_IF_ERROR(row.status());
    return Keys{
        .kek = std::get<0>(*row),
        .dek = std::get<1>(*row).get<std::string>(),
        .private_key = std::get<2>(*row).get<std::string>(),
    };
  }
  return absl::NotFoundError(absl::StrCat("Cannot find '", key_name, "'"));
}

absl::StatusOr<crypto::SecretData> UnwrapSecret(
    absl::string_view associated_data,
    privacy_sandbox::key_manager::GcpKmsClient& gcp_kms_client,
    const Keys& keys) {
  HATS_ASSIGN_OR_RETURN(
      std::string unwrapped_dek,
      gcp_kms_client.DecryptData(keys.kek, keys.dek, kAssociatedData));
  return crypto::Decrypt(crypto::SecretData(unwrapped_dek),
                         crypto::SecretData(keys.private_key), associated_data);
}

}  // namespace privacy_sandbox::key_manager
