#ifndef HATS_KEY_MANAGER_KMS_CLIENT_H
#define HATS_KEY_MANAGER_KMS_CLIENT_H

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/cloud/kms/v1/key_management_client.h"

// Defines an interface for interacting with a Key Management System (KMS)
// service.  This abstraction allows for the implementation to be swapped
// out with minimal code changes.  For example, the implementation could
// use the Google Cloud Platform KMS, or it could use a local KMS for
// testing purposes.
class KmsClient {
 public:
  virtual ~KmsClient() = default;

  virtual ::google::cloud::v2_25::StatusOr<google::cloud::kms::v1::PublicKey>
  GetPublicKey(std::string const& key_name) = 0;
  virtual ::google::cloud::v2_25::StatusOr<google::cloud::kms::v1::CryptoKey>
  CreateAsymmetricKey(std::string const& key_name,
                      std::string const& key_ring_id) = 0;
  virtual ::google::cloud::v2_25::StatusOr<
      google::cloud::kms::v1::EncryptResponse>
  EncryptData(std::string const& key_name, std::string const& plaintext) = 0;
  virtual google::cloud::v2_25::StatusOr<
      google::cloud::kms::v1::DecryptResponse>
  DecryptData(std::string const& key_name, std::string const& ciphertext) = 0;
};

#endif  // HATS_KEY_MANAGER_KMS_CLIENT
