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

#include "public_key/public-key-server.h"

#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "google/protobuf/empty.pb.h"
#include "google/protobuf/util/json_util.h"
#include "grpcpp/ext/proto_server_reflection_plugin.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "key_manager/public-key-fetcher.h"
#include "public_key/proto/public_key_service.pb.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_util.h"

namespace pcit::public_key_service {
grpc::Status PublicKeyServer::ListPublicKeys(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    ListPublicKeysResponse* response) {
  absl::StatusOr<std::vector<pcit::key_manager::PerOriginPublicKey>>
      onprem_public_key = fetcher_->GetLatestPublicKeys();
  if (!onprem_public_key.ok()) {
    return grpc::Status(
        grpc::StatusCode::UNAVAILABLE,
        absl::StrCat("failed to fetch some public keys from upstream: ",
                     " ONPREM: ", onprem_public_key.status()));
  }

  for (const pcit::key_manager::PerOriginPublicKey& key :
       (*onprem_public_key)) {
    PublicKey* onprem_key = response->add_public_keys();
    // Example existing key ID format:
    // 7F00000000000000
    // The existing keys are stored as HEX string in the database as STRING(50).
    onprem_key->set_key_id(absl::StrCat(absl::Hex(key.key_id)));
    // The public keys are returned in non websafe base64 escaped format and so
    // we need to do HEX conversion.
    std::string public_key_bytes;
    if (!absl::HexStringToBytes(key.public_key, &public_key_bytes))
      return grpc::Status(
          grpc::StatusCode::INTERNAL,
          "failed to convert onprem public key from hex to bytes");
    std::string public_key_base64_encoded =
        absl::Base64Escape(public_key_bytes);
    onprem_key->set_public_key(public_key_base64_encoded);
    onprem_key->set_origin(key.origin);
    onprem_key->set_execution_environment(EXECUTION_ENVIRONMENT_ONPREM);
  }

  return grpc::Status::OK;
}

grpc::Status PublicKeyServer::UpdateCloudBucket(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    google::protobuf::Empty* response) {
  ListPublicKeysResponse list_response;
  HATS_RETURN_IF_ERROR(ListPublicKeys(context, request, &list_response))
      .With(status_macro::FromAbslStatus);

  std::string json;
  HATS_RETURN_IF_ERROR(
      google::protobuf::util::MessageToJsonString(list_response, &json))
      .PrependWith("Failed to serialize json: ")
      .With(status_macro::FromAbslStatus);
  google::cloud::storage::ObjectWriteStream writer = bucket_client_.WriteObject(
      options_.gcp_cloud_bucket_name, "public_keys.json");
  writer << json;
  writer.Close();
  if (!writer.metadata()) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        absl::StrCat("failed to create object with error: ",
                                     writer.metadata().status().message()));
  }
  LOG(INFO) << "Successfully created object: " << *writer.metadata();
  return grpc::Status::OK;
}

PublicKeyServer::PublicKeyServer(
    const PublicKeyServerOptions& options,
    std::unique_ptr<pcit::key_manager::PublicKeyFetcher> fetcher,
    google::cloud::storage::Client bucket_client)
    : options_(options),
      fetcher_(std::move(fetcher)),
      bucket_client_(bucket_client) {}

void CreateAndStartPublicKeyServer(
    const PublicKeyServerOptions& options,
    std::unique_ptr<pcit::key_manager::PublicKeyFetcher> fetcher) {
  std::string server_address = absl::StrCat("0.0.0.0:", options.port);
  PublicKeyServer public_key_server(options, std::move(fetcher),
                                    google::cloud::storage::Client());
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(&public_key_server)
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();
}
}  // namespace pcit::public_key_service
