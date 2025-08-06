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

#include "client/trusted_application/enclave_app/trusted_application.h"

#include <string>
#include <vector>

#include "client/proto/orchestrator.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "client/sdk/hats_orchestrator_client.h"
#include "crypto/hpke-crypter.h"
#include "crypto/secret-data.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_util.h"

namespace pcit::client {

grpc::Status TrustedApplication::Echo(grpc::ServerContext* context,
                                      const EncryptedRequest* request,
                                      DecryptedResponse* response) {
  HATS_ASSIGN_OR_RETURN(
      std::vector<server_common::Key> keys, hats_orchestrator_client_.GetKeys(),
      _.PrependWith("Failed to fetch keys from the orchestrator: ")
          .With(status_macro::FromAbslStatus));

  server_common::Key key_to_use;
  bool key_found = false;
  for (const server_common::Key& key : keys) {
    if (key.key_id() == request->key_id()) {
      key_to_use = key;
      key_found = true;
      break;
    }
  }

  if (!key_found) {
    return grpc::Status(
        grpc::StatusCode::UNKNOWN,
        absl::StrCat("Decryption key not found, key id: ", request->key_id()));
  }

  crypto::SecretData decryption_key =
      crypto::SecretData(key_to_use.private_key());

  crypto::SecretData encrypted_data =
      crypto::SecretData(request->encrypted_message());
  HATS_ASSIGN_OR_RETURN(crypto::SecretData decrypted,
                        crypto::HpkeDecrypt(decryption_key, encrypted_data,
                                            pcit::crypto::kSecretHpkeAd),
                        _.PrependWith("Failed to decrypt message: ")
                            .With(status_macro::FromAbslStatus));

  *response->mutable_response() = decrypted.GetStringView();

  return grpc::Status::OK;
}

}  // namespace pcit::client
