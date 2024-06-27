#include "key_manager/gcp-kms-client.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "google/cloud/status.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/interceptor.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

google::cloud::v2_25::StatusOr<google::cloud::kms::v1::PublicKey> GetPublicKey(
    std::string const &key_name);
google::cloud::v2_25::StatusOr<google::cloud::kms::v1::CryptoKey>
CreateAsymmetricKey(std::string const &parent, std::string const &key_name,
                    google::cloud::kms::v1::CryptoKey const &crypto_key);
google::cloud::v2_25::StatusOr<google::cloud::kms::v1::EncryptResponse>
EncryptData(std::string const &key_name, std::string const &plaintext);
google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
DecryptData(std::string const &key_name, std::string const &ciphertext);

GcpKmsClient::GcpKmsClient(
    const std::string &project_id, const std::string &location_id,
    const std::string &key_ring_id,
    const std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
        client)
    : project_id_(std::move(project_id)),
      location_id_(std::move(location_id)),
      key_ring_id_(std::move(key_ring_id)),
      client_(client) {
  if (client_ == nullptr) {
    client_ =
        std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
            ::google::cloud::kms_v1::MakeKeyManagementServiceConnection());
  }
}

google::cloud::v2_25::StatusOr<google::cloud::kms::v1::PublicKey>
GcpKmsClient::GetPublicKey(std::string const &key_name) {
  google::cloud::kms::v1::GetPublicKeyRequest request;
  request.set_name(key_name);

  return client_->GetPublicKey(request);
}

google::cloud::v2_25::StatusOr<google::cloud::kms::v1::CryptoKey>
GcpKmsClient::CreateAsymmetricKey(
    std::string const &parent, std::string const &key_name,
    google::cloud::kms::v1::CryptoKey const &crypto_key) {
  google::cloud::kms::v1::CreateCryptoKeyRequest request;
  request.set_parent(parent);
  request.set_crypto_key_id(key_name);

  google::cloud::kms::v1::CryptoKey key;
  key.set_purpose(google::cloud::kms::v1::CryptoKey::ASYMMETRIC_SIGN);
  key.mutable_version_template()->set_algorithm(
      google::cloud::kms::v1::
          CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P256_SHA256);
  *request.mutable_crypto_key() = key;
  return client_->CreateCryptoKey(request);
}

google::cloud::v2_25::StatusOr<google::cloud::kms::v1::EncryptResponse>
GcpKmsClient::EncryptData(std::string const &key_name,
                          std::string const &plaintext) {
  google::cloud::kms::v1::EncryptRequest request;
  request.set_name(key_name);
  request.set_plaintext(plaintext);
  return client_->Encrypt(request);
}

google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
GcpKmsClient::DecryptData(std::string const &key_name,
                          std::string const &ciphertext) {
  google::cloud::kms::v1::DecryptRequest request;
  request.set_name(key_name);
  request.set_ciphertext(ciphertext);

  return client_->Decrypt(request);
}

}  // namespace privacy_sandbox::tvs
