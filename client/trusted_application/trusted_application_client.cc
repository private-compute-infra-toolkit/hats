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

#include "client/trusted_application/trusted_application_client.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "client/proto/trusted_service.grpc.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "grpcpp/create_channel.h"
#include "status_macro/status_macros.h"

namespace privacy_sandbox::client {

TrustedApplicationClient::TrustedApplicationClient(
    absl::string_view private_key, int8_t key_id)
    : trusted_service_stub_(TrustedService::NewStub(grpc::CreateChannel(
          std::string("localhost:8000"), grpc::InsecureChannelCredentials()))),
      private_key_(private_key),
      key_id_(key_id) {}

TrustedApplicationClient::TrustedApplicationClient(
    absl::string_view address, absl::string_view private_key, int8_t key_id)
    : trusted_service_stub_(TrustedService::NewStub(grpc::CreateChannel(
          std::string(address), grpc::InsecureChannelCredentials()))),
      private_key_(private_key),
      key_id_(key_id) {}

absl::StatusOr<DecryptedResponse> TrustedApplicationClient::SendEcho() const {
  return TrustedApplicationClient::SendEcho(kTestMessage);
}

absl::StatusOr<DecryptedResponse> TrustedApplicationClient::SendEcho(
    absl::string_view to_encrypt) const {
  grpc::ClientContext context;
  HATS_ASSIGN_OR_RETURN(std::string encrypted,
                        privacy_sandbox::crypto::Encrypt(
                            private_key_, crypto::SecretData(to_encrypt),
                            privacy_sandbox::crypto::kSecretAd));

  EncryptedRequest request;
  *request.mutable_encrypted_message() = std::move(encrypted);
  request.set_key_id(key_id_);

  DecryptedResponse response;

  HATS_RETURN_IF_ERROR(
      trusted_service_stub_->Echo(&context, request, &response))
      .PrependWith("Failed to decrypt message: ");

  return response;
}

}  // namespace privacy_sandbox::client
