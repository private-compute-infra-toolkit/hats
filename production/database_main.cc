/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * A helper CLI to create and update a database for TVS keys, shares and
 *  policies.
 * The CLI performs the following:
 * 1. Create a database that stores that TVS keys, DEKs, KEKs metadata, and
 *    policies. Users can use the `gcloud` CLI instead.
 * To create a database run the following:
 * database_main --operation=create_database \
 *               --spanner_database=<project>/<instance>/<database_id> \
 *               --key_resource_name=<kms_key_resource>
 * 2. Generate keys for TVS - keys for handshake.
 *    The CLI generates a DEK wrap it with a KEK in KMS and store it in the
 *    database. Wrap the TVS keys with the DEK and store them.
 * To generate TVS keys run the following:
 * database_main --operation=create_tvs_keys \
 *               --spanner_database=<project>/<instance>/<database_id>
 *               --key_resource_name=<kms_key_resource>
 * 3. Insert an appraisal policy from a file to the spanner database.
 * To insert an appraisal policy run the following:
 * database_main --operation=insert_appraisal_policy \
 *               --spanner_database=<project>/<instance>/<database_id> \
 *               --key_resource_name=<kms_key_resource> \
 *               --appraisal_policy_path=<path_to_appraisal_policy>
 * 4a. Register a user. The CLI generates an HPKE for the user, and generate a
 *    DEK. The CLI wraps the HPKE private key with the DEK, wrap DEK with KEK
 *    and store them.
 * To register a user run the following.
 * database_main --operation=register_user \
 * --spanner_database=<project>/<instance>/<database_id>
 * --key_resource_name=<kms_key_resource
 * --user_authentication_public_key=<user_public_key_in_hex_for_authentication>
 * --user_name=default --user_origin="http://example.com"
 * 4b. Register a user using split trust. The CLI generates an HPKE for the
 * user, and generate a DEK. The CLI splits the HPKE private key, wraps the
 * shares with the DEK, wrap DEK with KEK and store them. To register a user run
 * the following.
 * database_main --operation=register_user_split_trust \
 * --spanner_databases=<project1>/<instance1>/<database_id1>,<project2>/<instance2>/<database_id2>
 * --key_resource_name=<kms_key_resource1,kms_resource_name2>
 * --user_authentication_public_key=<user_public_key_in_hex_for_authentication>
 * --user_name=default --user_origin="http://example.com"
 */

#include <fstream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "crypto/secret-sharing.rs.h"
#include "gcp_common/gcp-status.h"
#include "google/cloud/spanner/admin/database_admin_client.h"
#include "google/cloud/spanner/client.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "key_manager/gcp-kms-client.h"
#include "openssl/aead.h"
#include "openssl/bn.h"
#include "openssl/ec_key.h"
#include "openssl/hpke.h"
#include "openssl/nid.h"
#include "proto/attestation/reference_value.pb.h"

ABSL_FLAG(std::string, operation, "create_database",
          "Describe the operation to be done. Valid values are: "
          "create_database, and populate_database");
ABSL_FLAG(std::string, spanner_database, "",
          "Spanner database to use in the following format "
          "<project_id>/<instance_id>/<database_id>");
ABSL_FLAG(std::vector<std::string>, spanner_databases,
          std::vector<std::string>({""}),
          "Comma separated list of spanner databases to use in the following "
          "format "
          "<project_id1>/<instance_id1>/<database_id1>,<project_id2>/"
          "<instance_id2>/<database_id2>");
ABSL_FLAG(std::string, key_resource_name, "", "Key resource name.");
ABSL_FLAG(
    std::vector<std::string>, key_resource_names,
    std::vector<std::string>({""}),
    "Comma separated list of spanner databases to use in the following format"
    "<Key resource name 1>, <Key resource name 2>");
ABSL_FLAG(std::string, appraisal_policy_path, "",
          "Path to an appraisal policy file");
ABSL_FLAG(std::string, user_authentication_public_key, "",
          "User public key for authentication. Uncompressed secp128r1 public "
          "key in hex format.");
ABSL_FLAG(std::string, user_name, "", "Name of the user.");
ABSL_FLAG(std::string, user_origin, "", "Origin of the user.");

namespace {

using ::privacy_sandbox::crypto::SecretData;

absl::StatusOr<google::cloud::spanner::Database> CreateSpannerDatabase(
    absl::string_view spanner_database) {
  std::vector<std::string> parts = absl::StrSplit(spanner_database, "/");
  if (parts.size() != 3) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid database name '", spanner_database,
                     "'. database name should be in the following format: "
                     "<project_id>/<instance_id>/<database_id>"));
  }
  return google::cloud::spanner::Database(/*project_id=*/parts[0],
                                          /*instance_Id=*/parts[1],
                                          /*database_id=*/parts[2]);
}

// Create a spanner database used to store TVS secrets.
absl::Status CreateDatabase(absl::string_view spanner_database) {
  absl::StatusOr<google::cloud::spanner::Database> database =
      CreateSpannerDatabase(spanner_database);
  if (!database.ok()) return database.status();

  google::spanner::admin::database::v1::CreateDatabaseRequest request;
  request.set_parent(database->instance().FullName());
  request.set_create_statement(
      absl::StrCat("CREATE DATABASE `", database->database_id(), "`"));

  // A sequence to generate key encryption key (KEK) IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE KekIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");

  // Table storing key encryption keys (KEK)s metadata. KEK resides in KMS and
  // never leaves. The table contains the following columns:
  // * KekId: a unique identifier for a KEK.
  // * ResourceName: KMS key resource name in the following format
  //   projects/<project_name>/location/<location>/KeyRings/<key_ring_name>/
  //   cryptoKeys/<key_name>.
  request.add_extra_statements(R"sql(
      CREATE TABLE KeyEncryptionKeys(
          KekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE KekIdSequence)),
          ResourceName STRING(1024) NOT NULL,
      ) PRIMARY KEY (KekId))sql");

  // Make sure that resource name is unique.
  request.add_extra_statements(R"sql(
      CREATE UNIQUE INDEX KekResourceNameIndex ON KeyEncryptionKeys
          (ResourceName))sql");

  // A sequence to generate data encryption key (DEK) IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE DekIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");

  // Table storing wrapped data encryption keys (DEK)s. DEKs are encrypted with
  // KekId. The table contains the following columns:
  // * DekId: a unique identifier for a DEK.
  // * KekId: specifies the KEK used to wrap the DEK.
  // * Dek: a DEK encrypted with KekId.
  request.add_extra_statements(R"sql(
      CREATE TABLE DataEncryptionKeys(
          DekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE DekIdSequence)),
          KekId INT64 NOT NULL,
          Dek  BYTES(MAX) NOT NULL,
      ) PRIMARY KEY (DekId))sql");

  // Table storing wrapped TVS private EC keys. The keys are used in the noise
  // protocol. The table contains the following columns:
  // * KeyId: a string used to identify the TVS key e.g. primary_key.
  // * DekId: specifies the DEK used to wrap the TVS key.
  // * PrivateKey: a TVS private key encrypted with DekId.
  request.add_extra_statements(R"sql(
      CREATE TABLE TVSPrivateKeys(
          KeyId STRING(1024),
          DekId INT64 NOT NULL,
          PrivateKey BYTES(MAX) NOT NULL,
      ) PRIMARY KEY (KeyId))sql");

  // Table storing TVS public keys. The public keys are stored in a separate
  // tables so that we can relax the ACLs on it.
  request.add_extra_statements(R"sql(
      CREATE TABLE TVSPublicKeys(
          KeyId STRING(1024),
          PublicKey String(MAX) NOT NULL,
      ) PRIMARY KEY (KeyId))sql");

  // A sequence to generate user IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE UserIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");

  // Table storing information about the registered users. Registered users
  // are the one allowed to use TVS. The table contains the following columns:
  // * UserId: a unique identifier for the user.
  // * Name: a name to identify the user.
  // * Origin: protocol, hostname, and port (in essence the URL used by the
  // user).
  request.add_extra_statements(R"sql(
      CREATE TABLE Users(
          UserId INT64 DEFAULT
                (GET_NEXT_SEQUENCE_VALUE(SEQUENCE UserIdSequence)),
          Name   STRING(1024) NOT NULL,
          Origin STRING(1024),
      ) PRIMARY KEY (UserId))sql");

  request.add_extra_statements(R"sql(
      CREATE UNIQUE INDEX UserNameIndex ON Users
          (Name))sql");

  // Table storing public keys used by a particular user. The table contains
  // the following columns:
  // * UserId: the ID of the user owning the private part of the given public
  //           key.
  // * PublicKey: the public part of the key that the user uses when
  //              authentcating with the TVS.
  request.add_extra_statements(R"sql(
      CREATE TABLE UserAuthenticationKeys(
          UserId INT64 NOT NULL,
          PublicKey BYTES(MAX) NOT NULL,
      ) PRIMARY KEY (UserId, PublicKey))sql");

  // A sequence to generate secret IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE SecretIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");
  // Table storing secrets to be returned to entities passing TVS attestation.
  // Secret could be full or partial HPKE keys or any arbitrary strings. The
  // stored secrets are wrapped with a DEK. The table contains the following
  // columns:
  // * SecretId: a unique identifier for secrets.
  // * UserId: the ID of the user owning the secret.
  // * DekId: specifies the DEK used to wrap the secret.
  // * Secret: a secret wrapped with DekId.
  // * UpdateTimestamp: timestamp of the last update to the row.
  request.add_extra_statements(R"sql(
      CREATE TABLE Secrets(
          SecretId INT64 DEFAULT
                        (GET_NEXT_SEQUENCE_VALUE(SEQUENCE SecretIdSequence)),
          UserId   INT64 NOT NULL,
          DekId    INT64 NOT NULL,
          Secret   BYTES(MAX) NOT NULL,
          UpdateTimestamp   TIMESTAMP NOT NULL,
      ) PRIMARY KEY (SecretId))sql");

  // Table storing public keys of the users. Right now we allow the user
  // to have only one secret and one public key.
  request.add_extra_statements(R"sql(
      CREATE TABLE UserPublicKeys(
          SecretId INT64 NOT NULL,
          UserId   INT64 NOT NULL,
          PublicKey STRING(1024) NOT NULL,
      ) PRIMARY KEY (SecretId))sql");

  // A sequence to generate policy IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE PolicyIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");
  // Table storing appraisal policies used to validate attestation report
  // against. columns:
  // * PolicyId: a string used to identify the appraisal policy.
  // * UpdateTimestamp: timestamp of the last update to the row.
  // * Policy: binary representation of the appraisal policy proto.
  request.add_extra_statements(R"sql(
      CREATE TABLE AppraisalPolicies(
          PolicyId          INT64 DEFAULT
                            (GET_NEXT_SEQUENCE_VALUE(SEQUENCE UserIdSequence)),
          Policy            BYTES(MAX) NOT NULL,
          UpdateTimestamp   TIMESTAMP NOT NULL,
      ) PRIMARY KEY (PolicyId))sql");

  google::cloud::spanner_admin::DatabaseAdminClient client(
      google::cloud::spanner_admin::MakeDatabaseAdminConnection());
  if (google::cloud::v2_25::StatusOr<
          google::spanner::admin::database::v1::Database>
          database = client.CreateDatabase(request).get();
      !database.ok()) {
    return privacy_sandbox::gcp_common::GcpToAbslStatus(database.status());
  }

  return absl::OkStatus();
}

// Helper class to generate EC keys.
class ECKey final {
 public:
  ECKey(const ECKey&) = delete;
  ECKey(ECKey&&) = default;
  ECKey& operator=(const ECKey&) = delete;
  ECKey& operator=(ECKey&&) = default;

  static absl::StatusOr<std::unique_ptr<ECKey>> Create() {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == nullptr) {
      return absl::InternalError("EC_KEY_new_by_curve_name() failed");
    }
    if (EC_KEY_generate_key(ec_key) != 1) {
      return absl::InternalError("EC Key generation failed");
    }
    return absl::WrapUnique(new ECKey(ec_key));
  }
  ~ECKey() { EC_KEY_free(ec_key_); }

  absl::StatusOr<std::string> WrapPrivateKey(
      const SecretData& wrapping_key) const {
    const BIGNUM* private_key_bn = EC_KEY_get0_private_key(ec_key_);
    SecretData private_key(BN_num_bytes(private_key_bn));
    if (!BN_bn2bin(private_key_bn, private_key.GetData())) {
      return absl::InternalError("BN_bn2bin() failed");
    }
    return privacy_sandbox::crypto::Encrypt(
        wrapping_key, private_key, privacy_sandbox::crypto::kTvsPrivateKeyAd);
  }

  absl::StatusOr<std::string> GetPublicKeyInHex() const {
    const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key_);
    const EC_GROUP* key_group = EC_KEY_get0_group(ec_key_);
    std::vector<uint8_t> key_data(65);
    size_t length =
        EC_POINT_point2oct(key_group, public_key, POINT_CONVERSION_UNCOMPRESSED,
                           reinterpret_cast<uint8_t*>(key_data.data()),
                           key_data.size(), /*ctx=*/nullptr);
    if (length != key_data.size()) {
      return absl::InternalError("EC_POINT_point2oct() failed.");
    }
    return absl::BytesToHexString(
        std::string(key_data.begin(), key_data.end()));
  }

 private:
  ECKey(EC_KEY* ec_key) : ec_key_(ec_key) {}

  EC_KEY* ec_key_;
};

struct TvsSecrets {
  std::string primary_ec_public_key;
  std::string secondary_ec_public_key;
  std::string wrapped_primary_ec_private_key;
  std::string wrapped_secondary_ec_private_key;
  std::string wrapped_dek;
};

// Generates secrets to be used in populating TVS database.
absl::StatusOr<TvsSecrets> GenerateTvsSecrets(
    absl::string_view kms_key_resource_name) {
  // Create EC Keys for TVS handshake.
  absl::StatusOr<std::unique_ptr<ECKey>> primary_ec_key = ECKey::Create();
  if (!primary_ec_key.ok()) {
    return primary_ec_key.status();
  }

  absl::StatusOr<std::unique_ptr<ECKey>> secondary_ec_key = ECKey::Create();
  if (!secondary_ec_key.ok()) {
    return secondary_ec_key.status();
  }

  // Get TVS public keys.
  absl::StatusOr<std::string> primary_ec_public_key =
      (*primary_ec_key)->GetPublicKeyInHex();
  if (!primary_ec_public_key.ok()) return primary_ec_public_key.status();

  absl::StatusOr<std::string> secondary_ec_public_key =
      (*secondary_ec_key)->GetPublicKeyInHex();
  if (!secondary_ec_public_key.ok()) return secondary_ec_public_key.status();

  // Generate data encryption key (DEK) to wrap keys.
  SecretData dek = privacy_sandbox::crypto::RandomAeadKey();

  // Wrap EC private keys with `dek`.
  absl::StatusOr<std::string> wrapped_primary_ec_private_key =
      (*primary_ec_key)->WrapPrivateKey(dek);
  if (!wrapped_primary_ec_private_key.ok())
    return wrapped_primary_ec_private_key.status();

  absl::StatusOr<std::string> wrapped_secondary_ec_private_key =
      (*secondary_ec_key)->WrapPrivateKey(dek);
  if (!wrapped_secondary_ec_private_key.ok())
    return wrapped_secondary_ec_private_key.status();

  // GCP KMS client.
  privacy_sandbox::key_manager::GcpKmsClient gcp_kms_client(
      google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection()));

  // Wrap DEK with KEK in KMS.
  absl::StatusOr<std::string> wrapped_dek = gcp_kms_client.EncryptData(
      kms_key_resource_name, dek.GetStringView(), "HATS_SECRET");
  if (!wrapped_dek.ok()) return wrapped_dek.status();

  // Wrap EC
  return TvsSecrets{
      .primary_ec_public_key = *std::move(primary_ec_public_key),
      .secondary_ec_public_key = *std::move(secondary_ec_public_key),
      .wrapped_primary_ec_private_key =
          *std::move(wrapped_primary_ec_private_key),
      .wrapped_secondary_ec_private_key =
          *std::move(wrapped_secondary_ec_private_key),
      .wrapped_dek = *std::move(wrapped_dek),
  };
}

absl::Status CreateTvsKeys(absl::string_view spanner_database,
                           absl::string_view kms_key_resource_name) {
  absl::StatusOr<google::cloud::spanner::Database> database =
      CreateSpannerDatabase(spanner_database);
  if (!database.ok()) return database.status();
  // Spanner client.
  google::cloud::spanner::Client spanner_client(
      google::cloud::spanner::MakeConnection(*database));
  absl::StatusOr<TvsSecrets> tvs_secrets =
      GenerateTvsSecrets(kms_key_resource_name);
  if (!tvs_secrets.ok()) return tvs_secrets.status();

  // Stash all inserts in the same transaction so we only commit if all inserts
  // succeed.
  auto commit = spanner_client.Commit(
      [&spanner_client, &kms_key_resource_name, &tvs_secrets = *tvs_secrets](
          google::cloud::spanner::Transaction transaction)
          -> google::cloud::StatusOr<google::cloud::spanner::Mutations> {
        std::optional<int64_t> kek_id;
        {
          // Check if the KMS key (KEK) is inserted.
          google::cloud::spanner::SqlStatement select(
              R"sql(
              SELECT
                  KekId
              FROM
                  KeyEncryptionKeys
              WHERE
                ResourceName = @resource_name)sql",
              {{"resource_name", google::cloud::spanner::Value(
                                     std::string(kms_key_resource_name))}});
          using RowType = std::tuple<int64_t>;
          auto rows =
              spanner_client.ExecuteQuery(transaction, std::move(select));
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            kek_id.emplace(std::get<0>(*row));
            break;
          }
        }
        if (!kek_id.has_value()) {
          // Insert Key-encryption-key (KEK) metadata, if not inserted
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  KeyEncryptionKeys (ResourceName)
              VALUES (@resource_name)
              THEN RETURN KekId)sql",
              {{"resource_name", google::cloud::spanner::Value(
                                     std::string(kms_key_resource_name))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, std::move(sql));
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            *kek_id = std::get<0>(*row);
          }
        }
        // Insert the wrapped dek.
        int64_t dek_id;
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  DataEncryptionKeys (KekId, Dek)
              VALUES (@kek_id, @dek)
              THEN RETURN DekId)sql",
              {{"kek_id", google::cloud::spanner::Value(*kek_id)},
               {"dek",
                google::cloud::spanner::Value(
                    google::cloud::spanner::Bytes(tvs_secrets.wrapped_dek))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, sql);
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            dek_id = std::get<0>(*row);
          }
        }
        // Insert the wrapped TVS EC private keys.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  TVSPrivateKeys(KeyId, DekId, PrivateKey)
              VALUES ("primary_key", @dek_id, @primary_key),
              ("secondary_key", @dek_id, @secondary_key))sql",
              {{"dek_id", google::cloud::spanner::Value(dek_id)},
               {"primary_key",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    tvs_secrets.wrapped_primary_ec_private_key))},
               {"secondary_key",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    tvs_secrets.wrapped_secondary_ec_private_key))}});
          if (auto inserted =
                  spanner_client.ExecuteDml(transaction, std::move(sql));
              !inserted.ok()) {
            return inserted.status();
          }
        }
        // Insert the TVS public keys in hex format for ease of querying.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  TVSPublicKeys(KeyId, PublicKey)
              VALUES ("primary_key", @primary_key),
              ("secondary_key", @secondary_key))sql",
              {{"primary_key", google::cloud::spanner::Value(
                                   tvs_secrets.primary_ec_public_key)},
               {"secondary_key", google::cloud::spanner::Value(
                                     tvs_secrets.secondary_ec_public_key)}});
          if (auto inserted = spanner_client.ExecuteDml(std::move(transaction),
                                                        std::move(sql));
              !inserted.ok()) {
            return inserted.status();
          }
        }
        return google::cloud::spanner::Mutations{};
      });

  if (!commit.ok()) {
    return privacy_sandbox::gcp_common::GcpToAbslStatus(commit.status());
  }

  std::cout << "Primary TVS Public Key: " << tvs_secrets->primary_ec_public_key
            << std::endl;
  std::cout << "Secondary TVS Public Key: "
            << tvs_secrets->secondary_ec_public_key << std::endl;
  return absl::OkStatus();
}

absl::StatusOr<oak::attestation::v1::ReferenceValues> ReadAppraisalPolicy(
    absl::string_view filename) {
  std::ifstream if_stream({std::string(filename)});
  if (!if_stream.is_open()) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to open: ", filename));
  }
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  oak::attestation::v1::ReferenceValues appraisal_policy;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policy)) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to parse: ", filename));
  }
  return appraisal_policy;
}

absl::Status InsertAppraisalPolicy(absl::string_view spanner_database,
                                   absl::string_view appraisal_policy_path) {
  absl::StatusOr<google::cloud::spanner::Database> database =
      CreateSpannerDatabase(spanner_database);
  if (!database.ok()) return database.status();
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      ReadAppraisalPolicy(appraisal_policy_path);
  if (!appraisal_policy.ok()) return appraisal_policy.status();

  // Spanner client.
  google::cloud::spanner::Client spanner_client(
      google::cloud::spanner::MakeConnection(*database));

  auto commit = spanner_client.Commit(
      [&spanner_client, &appraisal_policy = *appraisal_policy](
          google::cloud::spanner::Transaction transaction)
          -> google::cloud::StatusOr<google::cloud::spanner::Mutations> {
        // Insert the appraisal policy.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  AppraisalPolicies(UpdateTimestamp, Policy)
              VALUES (CURRENT_TIMESTAMP(), @policy))sql",
              {{"policy",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    appraisal_policy.SerializeAsString()))}});
          if (auto inserted = spanner_client.ExecuteDml(std::move(transaction),
                                                        std::move(sql));
              !inserted.ok()) {
            return inserted.status();
          }
        }
        return google::cloud::spanner::Mutations{};
      });

  if (!commit.ok()) {
    return privacy_sandbox::gcp_common::GcpToAbslStatus(commit.status());
  }

  return absl::OkStatus();
}

// Helper class to generate HPKE key pairs.
class HPKEKey {
 public:
  static absl::StatusOr<std::unique_ptr<HPKEKey>> Create() {
    auto hpke_key = absl::WrapUnique(new HPKEKey());
    if (absl::Status status = hpke_key->Init(); !status.ok()) {
      return status;
    }
    return hpke_key;
  }

  absl::StatusOr<std::string> GetPublicKeyInHex() const {
    uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
    size_t public_key_len;
    if (!EVP_HPKE_KEY_public_key(key_.get(), public_key, &public_key_len,
                                 sizeof(public_key))) {
      return absl::InternalError("EVP_HPKE_KEY_public_key() failed.");
    }
    BIGNUM* public_key_bn =
        BN_bin2bn(public_key, public_key_len, /*ret=*/nullptr);
    if (public_key_bn == nullptr) {
      return absl::InternalError("BN_bin2bn() failed.");
    }
    char* public_key_hex = BN_bn2hex(public_key_bn);
    if (public_key_hex == nullptr) {
      return absl::InternalError("BN_bn2hex() failed.");
    }
    BN_free(public_key_bn);
    return public_key_hex;
  }

  absl::StatusOr<SecretData> GetPrivateKey() const {
    SecretData private_key(EVP_HPKE_MAX_PRIVATE_KEY_LENGTH);
    size_t private_key_len;
    if (!EVP_HPKE_KEY_private_key(key_.get(), private_key.GetData(),
                                  &private_key_len, private_key.GetSize())) {
      return absl::InternalError("EVP_HPKE_KEY_private_key() failed.");
    }
    absl::Status status = private_key.Resize(private_key_len);
    if (!status.ok()) return status;
    return private_key;
  }

 private:
  HPKEKey() {}

  absl::Status Init() {
    if (!EVP_HPKE_KEY_generate(key_.get(), EVP_hpke_x25519_hkdf_sha256())) {
      return absl::InternalError("EVP_HPKE_KEY_generate() failed");
    }
    return absl::OkStatus();
  }
  bssl::ScopedEVP_HPKE_KEY key_;
};

struct WrappedSecrets {
  std::string wrapped_user_secret;
  std::string wrapped_dek;
};

// Wrap secrets: generate a Dek, wrap Dek with Kek, and wrap user's secret -
// full or portion of Hpke private key - with `Dek`.
absl::StatusOr<WrappedSecrets> WrapSecret(
    absl::string_view kms_key_resource_name, const SecretData& user_secret) {
  // Generate data encryption key (DEK) to wrap keys and secrets.
  SecretData dek = privacy_sandbox::crypto::RandomAeadKey();
  // Wrap secret - returned by TVS after successful attestation verification -
  // with DEK.
  absl::StatusOr<std::string> wrapped_user_secret =
      privacy_sandbox::crypto::Encrypt(dek, user_secret,
                                       privacy_sandbox::crypto::kSecretAd);
  if (!wrapped_user_secret.ok()) return wrapped_user_secret.status();
  privacy_sandbox::key_manager::GcpKmsClient gcp_kms_client(
      google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection()));

  // Wrap DEK with KEK in KMS.
  absl::StatusOr<std::string> wrapped_dek = gcp_kms_client.EncryptData(
      kms_key_resource_name, dek.GetStringView(), "HATS_SECRET");
  if (!wrapped_dek.ok()) return wrapped_dek.status();

  return WrappedSecrets{
      .wrapped_user_secret = *std::move(wrapped_user_secret),
      .wrapped_dek = *std::move(wrapped_dek),
  };
}

absl::StatusOr<std::vector<SecretData>> SplitSecret(int num_shares,
                                                    int threshold,
                                                    const SecretData& secret) {
  absl::StatusOr<rust::Vec<rust::String>> shares =
      privacy_sandbox::crypto::SplitSecret(
          rust::Slice<const std::uint8_t>(secret.GetData(), secret.GetSize()),
          num_shares, threshold);
  if (!shares.ok()) return shares.status();
  std::vector<SecretData> result;
  for (const rust::String& share : *shares) {
    result.push_back(SecretData(static_cast<std::string>(share)));
  }
  return result;
}

absl::Status RegisterUserInternal(
    absl::string_view spanner_database, absl::string_view kms_key_resource_name,
    absl::string_view user_authentication_public_key,
    absl::string_view user_name, absl::string_view user_origin,
    absl::string_view user_public_key, const SecretData& user_secret) {
  std::string user_authentication_public_key_hex;
  if (!absl::HexStringToBytes(user_authentication_public_key,
                              &user_authentication_public_key_hex)) {
    return absl::InvalidArgumentError(
        "Failed to parse user public key. The key should be in formatted as "
        "hex string.");
  }
  absl::StatusOr<WrappedSecrets> wrapped_secrets =
      WrapSecret(kms_key_resource_name, user_secret);
  if (!wrapped_secrets.ok()) return wrapped_secrets.status();

  absl::StatusOr<google::cloud::spanner::Database> database =
      CreateSpannerDatabase(spanner_database);
  if (!database.ok()) return database.status();
  // Spanner client.
  google::cloud::spanner::Client spanner_client(
      google::cloud::spanner::MakeConnection(*database));

  // Stash all inserts in the same transaction so we only commit if all inserts
  // succeed.
  auto commit = spanner_client.Commit(
      [&user_authentication_public_key_hex, &user_name, &user_origin,
       &spanner_client, &user_public_key, &kms_key_resource_name,
       &wrapped_secrets =
           *wrapped_secrets](google::cloud::spanner::Transaction transaction)
          -> google::cloud::StatusOr<google::cloud::spanner::Mutations> {
        std::optional<int64_t> kek_id;
        {
          // Check if the KMS key (KEK) is inserted.
          google::cloud::spanner::SqlStatement select(
              R"sql(
              SELECT
                  KekId
              FROM
                  KeyEncryptionKeys
              WHERE
                ResourceName = @resource_name)sql",
              {{"resource_name", google::cloud::spanner::Value(
                                     std::string(kms_key_resource_name))}});
          using RowType = std::tuple<int64_t>;
          auto rows =
              spanner_client.ExecuteQuery(transaction, std::move(select));
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            kek_id.emplace(std::get<0>(*row));
            break;
          }
        }
        if (!kek_id.has_value()) {
          // Insert Key-encryption-key (KEK) metadata, if not inserted
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  KeyEncryptionKeys (ResourceName)
              VALUES (@resource_name)
              THEN RETURN KekId)sql",
              {{"resource_name", google::cloud::spanner::Value(
                                     std::string(kms_key_resource_name))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, std::move(sql));
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            *kek_id = std::get<0>(*row);
          }
        }
        // Insert the wrapped dek.
        int64_t dek_id;
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  DataEncryptionKeys (KekId, Dek)
              VALUES (@kek_id, @dek)
              THEN RETURN DekId)sql",
              {{"kek_id", google::cloud::spanner::Value(*kek_id)},
               {"dek",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    wrapped_secrets.wrapped_dek))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, sql);
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            dek_id = std::get<0>(*row);
          }
        }
        // Insert user info.
        int64_t user_id;
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  Users(Name, Origin)
              VALUES (@name, @origin)
              THEN RETURN UserId)sql",
              {{"name", google::cloud::spanner::Value(std::string(user_name))},
               {"origin",
                google::cloud::spanner::Value(std::string(user_origin))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, sql);
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            user_id = std::get<0>(*row);
          }
        }
        // Insert the user's public key.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  UserAuthenticationKeys(UserId, PublicKey)
              VALUES (@user_id, @public_key))sql",
              {{"user_id", google::cloud::spanner::Value(user_id)},
               {"public_key",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    user_authentication_public_key_hex))}});
          if (auto inserted =
                  spanner_client.ExecuteDml(transaction, std::move(sql));
              !inserted.ok()) {
            return inserted.status();
          }
        }
        int64_t secret_id;
        // Insert the wrapped secret.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  Secrets(UserId, DekId, Secret, UpdateTimestamp)
              VALUES (@user_id, @dek_id, @secret, CURRENT_TIMESTAMP())
              THEN RETURN SecretId)sql",
              {{"user_id", google::cloud::spanner::Value(user_id)},
               {"dek_id", google::cloud::spanner::Value(dek_id)},
               {"secret",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    wrapped_secrets.wrapped_user_secret))}});
          auto rows = spanner_client.ExecuteQuery(transaction, std::move(sql));
          using RowType = std::tuple<int64_t>;
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            secret_id = std::get<0>(*row);
          }
        }
        // Insert the public key part of the secret.
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  UserPublicKeys(SecretId, UserId, PublicKey)
              VALUES (@secret_id, @user_id, @public_key))sql",
              {{"secret_id", google::cloud::spanner::Value(secret_id)},
               {"user_id", google::cloud::spanner::Value(user_id)},
               {"public_key",
                google::cloud::spanner::Value(std::string(user_public_key))}});
          if (auto inserted = spanner_client.ExecuteDml(std::move(transaction),
                                                        std::move(sql));
              !inserted.ok()) {
            return inserted.status();
          }
        }
        return google::cloud::spanner::Mutations{};
      });

  if (!commit.ok()) {
    return privacy_sandbox::gcp_common::GcpToAbslStatus(commit.status());
  }

  std::cout << "Public portion of secret: " << user_public_key << "\n";
  return absl::OkStatus();
}

absl::Status RegisterUserSplitTrust(
    const std::vector<std::string>& spanner_databases,
    const std::vector<std::string>& kms_key_resource_names,
    absl::string_view user_authentication_public_key,
    absl::string_view user_name, absl::string_view user_origin) {
  if (spanner_databases.size() != kms_key_resource_names.size()) {
    return absl::FailedPreconditionError(
        "Number of KMS key resources should be equivalent to the number of "
        "Spanner databases.");
  }
  absl::StatusOr<std::unique_ptr<HPKEKey>> hpke_key = HPKEKey::Create();
  if (!hpke_key.ok()) return hpke_key.status();
  absl::StatusOr<std::string> user_public_key =
      (*hpke_key)->GetPublicKeyInHex();
  if (!user_public_key.ok()) return user_public_key.status();
  absl::StatusOr<SecretData> user_private_key = (*hpke_key)->GetPrivateKey();
  if (!user_private_key.ok()) return user_private_key.status();

  int num_shares = spanner_databases.size();
  int threshold = num_shares - 1;
  absl::StatusOr<std::vector<SecretData>> shares =
      SplitSecret(num_shares, threshold, *user_private_key);
  if (!shares.ok()) return shares.status();

  if (shares->size() != spanner_databases.size()) {
    return absl::InternalError(
        "Number of shares is not equal to the number of spanner databases.");
  }

  for (size_t i = 0; i < spanner_databases.size(); i++) {
    absl::Status register_user =
        RegisterUserInternal(spanner_databases[i], kms_key_resource_names[i],
                             user_authentication_public_key, user_name,
                             user_origin, *user_public_key, (*shares)[i]);
    if (!register_user.ok()) return register_user;
  }
  return absl::OkStatus();
}

absl::Status RegisterUser(std::string spanner_database,
                          std::string kms_key_resource_name,
                          absl::string_view user_authentication_public_key,
                          absl::string_view user_name,
                          absl::string_view user_origin) {
  absl::StatusOr<std::unique_ptr<HPKEKey>> hpke_key = HPKEKey::Create();
  if (!hpke_key.ok()) return hpke_key.status();
  absl::StatusOr<std::string> derived_pub_key =
      (*hpke_key)->GetPublicKeyInHex();
  if (!derived_pub_key.ok()) return derived_pub_key.status();
  absl::StatusOr<SecretData> user_private_key = (*hpke_key)->GetPrivateKey();
  if (!user_private_key.ok()) return user_private_key.status();
  return RegisterUserInternal(spanner_database, kms_key_resource_name,
                              user_authentication_public_key, user_name,
                              user_origin, *derived_pub_key, *user_private_key);
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  std::string operation = absl::GetFlag(FLAGS_operation);
  if (operation == "create_database") {
    if (absl::Status status =
            CreateDatabase(absl::GetFlag(FLAGS_spanner_database));
        !status.ok()) {
      LOG(ERROR) << "Failed to create database: " << status;
      return 1;
    }
  } else if (operation == "create_tvs_keys") {
    if (absl::Status status =
            CreateTvsKeys(absl::GetFlag(FLAGS_spanner_database),
                          absl::GetFlag(FLAGS_key_resource_name));
        !status.ok()) {
      LOG(ERROR) << "Failed to populate database: " << status;
      return 1;
    }
  } else if (operation == "insert_appraisal_policy") {
    if (absl::Status status =
            InsertAppraisalPolicy(absl::GetFlag(FLAGS_spanner_database),
                                  absl::GetFlag(FLAGS_appraisal_policy_path));
        !status.ok()) {
      LOG(ERROR) << "Failed to insert an appraisal policy: " << status;
      return 1;
    }

  } else if (operation == "register_user") {
    if (absl::Status status = RegisterUser(
            absl::GetFlag(FLAGS_spanner_database),
            absl::GetFlag(FLAGS_key_resource_name),
            absl::GetFlag(FLAGS_user_authentication_public_key),
            absl::GetFlag(FLAGS_user_name), absl::GetFlag(FLAGS_user_origin));
        !status.ok()) {
      LOG(ERROR) << "Failed to register user: " << status;
      return 1;
    }
  } else if (operation == "register_user_split_trust") {
    if (absl::Status status = RegisterUserSplitTrust(
            absl::GetFlag(FLAGS_spanner_databases),
            absl::GetFlag(FLAGS_key_resource_names),
            absl::GetFlag(FLAGS_user_authentication_public_key),
            absl::GetFlag(FLAGS_user_name), absl::GetFlag(FLAGS_user_origin));
        !status.ok()) {
      LOG(ERROR) << "Failed to register user: " << status;
      return 1;
    }
  }
  return 0;
}
