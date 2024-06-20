#ifndef HATS_KEY_MANAGER_GCP_KEY_MANAGER_H
#define HATS_KEY_MANAGER_GCP_KEY_MANAGER_H

#include <string>

#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/location.h"
#include "key_manager/kms-client.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {
class GcpKmsClient : public KmsClient {
 public:
  explicit GcpKmsClient(
      std::string const &project_id, std::string const &location_id,
      std::string const &key_ring_id,
      const std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
          client_);
  GcpKmsClient() = delete;

  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::PublicKey>
  GetPublicKey(std::string const &key_name);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::CryptoKey>
  CreateAsymmetricKey(std::string const &parent, std::string const &key_name,
                      google::cloud::kms::v1::CryptoKey const &crypto_key);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::EncryptResponse>
  EncryptData(std::string const &key_name, std::string const &plaintext);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
  DecryptData(std::string const &key_name, std::string const &ciphertext);

 private:
  const std::string project_id_;
  const std::string location_id_;
  const std::string key_ring_id_;
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient> client_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_KEY_MANAGER_GCP_KEY_MANAGER_
