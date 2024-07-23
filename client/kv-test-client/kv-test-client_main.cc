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

#include <iostream>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "external/kv-server/public/query/v2/get_values_v2.grpc.pb.h"
#include "external/kv-server/public/query/v2/get_values_v2.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "quiche/binary_http/binary_http_message.h"
#include "quiche/oblivious_http/oblivious_http_client.h"

ABSL_FLAG(std::string, kv_server, "localhost:50051", "KV server address.");
ABSL_FLAG(std::string, public_key, "",
          "HPKE public key to encrypt KV ObliviousGetValuesRequest");

namespace {

constexpr char kTestRequest[] = R"json({
  "metadata": {
    "hostname": "example.com"
  },
  "partitions": [
    {
      "id": 0,
      "compressionGroupId": 0,
      "arguments": [
        {
          "tags": [
            "structured",
            "groupNames"
          ],
          "data": [
            "foo0"
          ]
        }
      ]
    }
  ]
})json";

absl::StatusOr<std::string> GetHpkePublicKey() {
  std::string public_key_bytes;
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_public_key),
                              &public_key_bytes)) {
    return absl::InvalidArgumentError("Cannot convert --public_key to bytes");
  }
  return public_key_bytes;
}

absl::StatusOr<std::string> SendV2GetValueRequest(const std::string& kv_server,
                                                  const std::string& request) {
  std::shared_ptr<grpc::Channel> channel =
      grpc::CreateChannel(kv_server, grpc::InsecureChannelCredentials());
  std::unique_ptr<kv_server::v2::KeyValueService::Stub> stub =
      kv_server::v2::KeyValueService::NewStub(channel);

  // Create BHTTP Request;
  quiche::BinaryHttpRequest binary_http_request({});
  binary_http_request.set_body(request);

  // Create Key Config.
  // KEM: DHKEM(X25519, HKDF-SHA256)
  const uint16_t kKEMParameter = 0x0020;
  // KDF: HKDF-SHA256
  const uint16_t kKDFParameter = 0x0001;
  // AEAD: AES-256-GCM
  const uint16_t kAEADParameter = 0x0002;
  absl::StatusOr<quiche::ObliviousHttpHeaderKeyConfig> ohttp_key_config =
      quiche::ObliviousHttpHeaderKeyConfig::Create(
          /*key_id=*/64, kKEMParameter, kKDFParameter, kAEADParameter);
  if (!ohttp_key_config.ok()) {
    return ohttp_key_config.status();
  }

  // Get the public key.
  absl::StatusOr<std::string> public_key = GetHpkePublicKey();
  if (!public_key.ok()) {
    return public_key.status();
  }

  // Create a client to encrypt/decrypt requests.
  absl::StatusOr<quiche::ObliviousHttpClient> client =
      quiche::ObliviousHttpClient::Create(*public_key, *ohttp_key_config);
  if (!client.ok()) {
    return client.status();
  }

  // Encrypt the request.
  absl::StatusOr<quiche::ObliviousHttpRequest> encrypted_ohttp_request =
      client->CreateObliviousHttpRequest(*binary_http_request.Serialize());

  kv_server::v2::ObliviousGetValuesRequest oblivious_get_value_request;
  oblivious_get_value_request.mutable_raw_body()->set_data(
      encrypted_ohttp_request->EncapsulateAndSerialize());
  grpc::ClientContext context;
  google::api::HttpBody response;

  // Send the request to KV-server
  grpc::Status status = stub->ObliviousGetValues(
      &context, oblivious_get_value_request, &response);
  if (!status.ok()) {
    return absl::UnknownError(
        absl::StrCat("Failed to send request: ", status.error_message()));
  }

  // Decrypt the response.
  // Use the context from the request.
  quiche::ObliviousHttpRequest::Context ohttp_context =
      std::move(*encrypted_ohttp_request).ReleaseContext();
  absl::StatusOr<quiche::ObliviousHttpResponse> ohttp_response =
      client->DecryptObliviousHttpResponse(response.data(), ohttp_context);
  return ohttp_response->GetPlaintextData();
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  absl::StatusOr<std::string> response =
      SendV2GetValueRequest(absl::GetFlag(FLAGS_kv_server), kTestRequest);
  if (!response.ok()) {
    LOG(ERROR) << "Failed to send V2GetValueRequest: " << response;
  }
  std::cout << "Response from KV-Server: " << *response << std::endl;
  return 0;
}
