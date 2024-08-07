/*
 * Copyright 2023 Google LLC
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

// A helper CLI to create and populate a database holding TVS keys and shares.
// The CLI performs the following:
// 1. Generate keys for TVS - keys for handshake and HPKE keys to be returned to
// clients passing the attestation verification.
//    The CLI generates a DEK wrap it with a KEK in KMS and store it in the
//    database. Wrap the TVS keys with the DEK and store them.
// 2. Create a database that stores that TVS keys, DEKs, and KEKs metadata. User
// can use the `gcloud` CLI instead.
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "google/cloud/spanner/admin/database_admin_client.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/gcp-status.h"
#include "openssl/aead.h"
#include "openssl/bn.h"
#include "openssl/ec_key.h"
#include "openssl/hpke.h"
#include "openssl/nid.h"

ABSL_FLAG(std::string, operation, "create_database",
          "Describe the operation to be done. Valid values are: "
          "create_database, and populate_database");
ABSL_FLAG(std::string, database_name, "", "Database name");
ABSL_FLAG(std::string, instance_id, "", "Instance ID");
ABSL_FLAG(std::string, project_id, "", "Project ID");
ABSL_FLAG(std::string, key_resource_name, "", "Key resource name.");

namespace {

using ::privacy_sandbox::crypto::SecretData;

// Create a spanner database used to store TVS secrets.
absl::Status CreateDatabase(absl::string_view project_id,
                            absl::string_view instance_id,
                            absl::string_view database_id) {
  google::cloud::spanner::Database database({std::string(project_id),
                                             std::string(instance_id),
                                             std::string(database_id)});
  google::spanner::admin::database::v1::CreateDatabaseRequest request;
  request.set_parent(database.instance().FullName());
  request.set_create_statement(
      absl::StrCat("CREATE DATABASE `", database.database_id(), "`"));

  // A sequence to generate key encryption key (KEK) IDs.
  request.add_extra_statements(R"sql(
      CREATE SEQUENCE KekIdSequence OPTIONS (
      sequence_kind="bit_reversed_positive"))sql");

  // Table storing key encryption keys (KEK)s metadata. KEK resides in KMS and
  // never leaves. The table contains the following columns:
  // * KekId: a unique identifier for a KEK.
  // * ResourceName: KMS key resource name in the following format
  //   projects/<project_name>/location/<location>/KeyRings/<key_ring_name>/cryptoKeys/<key_name>.
  request.add_extra_statements(R"sql(
      CREATE TABLE KeyEncryptionKey(
          KekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE KekIdSequence)),
          ResourceName STRING(1024),
      ) PRIMARY KEY (KekId))sql");

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
      CREATE TABLE DataEncryptionKey(
          DekId INT64 DEFAULT (GET_NEXT_SEQUENCE_VALUE(SEQUENCE DekIdSequence)),
          KekId INT64 NOT NULL,
          Dek  BYTES(MAX),
      ) PRIMARY KEY (DekId))sql");

  // Table storing wrapped TVS private EC keys. The keys are used in the noise
  // protocol. The table contains the following columns:
  // * KeyId: a string used to identify the TVS key e.g. primary_key.
  // * DekId: specifies the DEK used to wrap the TVS key.
  // * PrivateKey: a TVS private key encrypted with DekId.
  request.add_extra_statements(R"sql(
      CREATE TABLE ECKeys(
          KeyId STRING(1024),
          DekId INT64 NOT NULL,
          PrivateKey BYTES(MAX),
      ) PRIMARY KEY (KeyId))sql");

  // Table storing secrets to be returned to entities passing TVS attestation.
  // Secret could be full or partial HPKE keys or any arbitrary strings. The
  // stored secrets are wrapped with a DEK. The table contains the following
  // columns:
  // * SecretId: a string used to identify the secret e.g. client name.
  // * DekId: specifies the DEK used to wrap the secret.
  // * Secret: a secret wrapped with DekId.
  request.add_extra_statements(R"sql(
      CREATE TABLE Secrets(
          SecretId STRING(1024),
          DekId    INT64 NOT NULL,
          Secret   BYTES(MAX)
      ) PRIMARY KEY (SecretId))sql");

  google::cloud::spanner_admin::DatabaseAdminClient client(
      google::cloud::spanner_admin::MakeDatabaseAdminConnection());
  if (google::cloud::v2_25::StatusOr<
          google::spanner::admin::database::v1::Database>
          database = client.CreateDatabase(request).get();
      !database.ok()) {
    return privacy_sandbox::key_manager::GcpToAbslStatus(database.status());
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

  absl::StatusOr<std::string> WrapPrivateKey(
      const SecretData& wrapping_key) const {
    SecretData private_key(EVP_HPKE_MAX_PRIVATE_KEY_LENGTH);
    size_t private_key_len;
    if (!EVP_HPKE_KEY_private_key(key_.get(), private_key.GetData(),
                                  &private_key_len, private_key.GetSize())) {
      return absl::InternalError("EVP_HPKE_KEY_private_key() failed.");
    }
    absl::Status status = private_key.Resize(private_key_len);
    if (!status.ok()) return status;
    return privacy_sandbox::crypto::Encrypt(wrapping_key, private_key,
                                            privacy_sandbox::crypto::kSecretAd);
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

struct Secrets {
  std::string primary_ec_public_key;
  std::string secondary_ec_public_key;
  std::string wrapped_primary_ec_private_key;
  std::string wrapped_secondary_ec_private_key;
  std::string wrapped_secret;
  std::string secret_public;
  std::string wrapped_dek;
};

// Generates secrets to be used in populating TVS database.
absl::StatusOr<Secrets> GenerateSecrets(
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

  // Generate data encryption key (DEK) to wrap keys and secrets.
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

  // Wrap secret - returned by TVS after successful attestation verification -
  // with DEK.
  absl::StatusOr<std::unique_ptr<HPKEKey>> hpke_key = HPKEKey::Create();
  if (!hpke_key.ok()) return hpke_key.status();
  absl::StatusOr<std::string> wrapped_secret = (*hpke_key)->WrapPrivateKey(dek);
  if (!wrapped_secret.ok()) return wrapped_secret.status();
  absl::StatusOr<std::string> secret_public = (*hpke_key)->GetPublicKeyInHex();
  if (!secret_public.ok()) return secret_public.status();

  // GCP KMS client.
  privacy_sandbox::key_manager::GcpKmsClient gcp_kms_client(
      google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection()));

  // Wrap DEK with KEK in KMS.
  absl::StatusOr<std::string> wrapped_dek = gcp_kms_client.EncryptData(
      kms_key_resource_name, dek.GetStringView(), "HATS_SECRET");
  if (!wrapped_dek.ok()) return wrapped_dek.status();

  // Wrap EC
  return Secrets{
      .primary_ec_public_key = *std::move(primary_ec_public_key),
      .secondary_ec_public_key = *std::move(secondary_ec_public_key),
      .wrapped_primary_ec_private_key =
          *std::move(wrapped_primary_ec_private_key),
      .wrapped_secondary_ec_private_key =
          *std::move(wrapped_secondary_ec_private_key),
      .wrapped_secret = *std::move(wrapped_secret),
      .secret_public = *std::move(secret_public),
      .wrapped_dek = *std::move(wrapped_dek),
  };
}

absl::Status PopulateDatabase(absl::string_view project_id,
                              absl::string_view instance_id,
                              absl::string_view database_id,
                              absl::string_view kms_key_resource_name) {
  // Spanner client.
  google::cloud::spanner::Client spanner_client(
      google::cloud::spanner::MakeConnection(google::cloud::spanner::Database(
          std::string(project_id), std::string(instance_id),
          std::string(database_id))));
  absl::StatusOr<Secrets> secrets = GenerateSecrets(kms_key_resource_name);
  if (!secrets.ok()) return secrets.status();

  // Stash all inserts in the same transaction so we only commit if all inserts
  // succeed.
  auto commit = spanner_client.Commit(
      [&spanner_client, &kms_key_resource_name,
       &secrets = *secrets](google::cloud::spanner::Transaction transaction)
          -> google::cloud::StatusOr<google::cloud::spanner::Mutations> {
        // Insert Key-encryption-key (KEK) metadata.
        int64_t kek_id;
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  KeyEncryptionKey (ResourceName)
              VALUES (@resource_name)
              THEN RETURN KekId)sql",
              {{"resource_name", google::cloud::spanner::Value(
                                     std::string(kms_key_resource_name))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, std::move(sql));
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            kek_id = std::get<0>(*row);
          }
        }
        // Insert the wrapped dek.
        int64_t dek_id;
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  DataEncryptionKey (KekId, Dek)
              VALUES (@kek_id, @dek)
              THEN RETURN DekId)sql",
              {{"kek_id", google::cloud::spanner::Value(kek_id)},
               {"dek",
                google::cloud::spanner::Value(
                    google::cloud::spanner::Bytes(secrets.wrapped_dek))}});
          using RowType = std::tuple<int64_t>;
          auto rows = spanner_client.ExecuteQuery(transaction, sql);
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
            dek_id = std::get<0>(*row);
          }
        }

        {
          // Insert the wrapped EC private keys.
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  ECKeys(KeyId, DekId, PrivateKey)
              VALUES ("primary_key", @dek_id, @primary_key),
              ("secondary_key", @dek_id, @secondary_key))sql",
              {{"dek_id", google::cloud::spanner::Value(dek_id)},
               {"primary_key",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    secrets.wrapped_primary_ec_private_key))},
               {"secondary_key",
                google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                    secrets.wrapped_secondary_ec_private_key))}});
          auto rows = spanner_client.ExecuteQuery(transaction, std::move(sql));
          using RowType = std::tuple<std::string, int64_t, std::string>;
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
          }
        }

        // Insert the wrapped secret
        {
          google::cloud::spanner::SqlStatement sql(
              R"sql(INSERT INTO  Secrets(SecretId, DekId, Secret)
              VALUES ("default", @dek_id, @secret))sql",
              {{"dek_id", google::cloud::spanner::Value(dek_id)},
               {"secret",
                google::cloud::spanner::Value(
                    google::cloud::spanner::Bytes(secrets.wrapped_secret))}});
          auto rows = spanner_client.ExecuteQuery(std::move(transaction),
                                                  std::move(sql));
          using RowType = std::tuple<std::string, int64_t, std::string>;
          for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
            if (!row.ok()) return row.status();
          }
        }
        return google::cloud::spanner::Mutations{};
      });

  if (!commit.ok()) {
    return privacy_sandbox::key_manager::GcpToAbslStatus(commit.status());
  }

  std::cout << "Primary TVS Public Key: " << secrets->primary_ec_public_key
            << std::endl;
  std::cout << "Secondary TVS Public Key: " << secrets->secondary_ec_public_key
            << std::endl;
  std::cout << "Public portion of secret: " << secrets->secret_public << "\n";
  return absl::OkStatus();
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  if (absl::GetFlag(FLAGS_operation) == "create_database") {
    if (absl::Status status = CreateDatabase(
            absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_instance_id),
            absl::GetFlag(FLAGS_database_name));
        !status.ok()) {
      LOG(ERROR) << "Failed to create database: " << status;
      return 1;
    }
  } else if (absl::GetFlag(FLAGS_operation) == "populate_database") {
    if (absl::Status status = PopulateDatabase(
            absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_instance_id),
            absl::GetFlag(FLAGS_database_name),
            absl::GetFlag(FLAGS_key_resource_name));
        !status.ok()) {
      LOG(ERROR) << "Failed to populate database; " << status;
      return 1;
    }
  }
  return 0;
}
