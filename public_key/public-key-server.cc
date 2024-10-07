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
#include "curl/curl.h"
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

namespace privacy_sandbox::public_key_service {
namespace {
size_t ResponseHandler(char* contents, size_t byte_size, size_t num_bytes,
                       std::string* output) {
  output->append(contents, byte_size * num_bytes);
  return byte_size * num_bytes;
}
absl::StatusOr<std::string> DownloadPublicKeys(const std::string& url) {
  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    return absl::UnknownError("null curl_api is not allowed");
  }
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ResponseHandler);
  std::string certificate;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &certificate);
  if (CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
    curl_easy_cleanup(curl);
    return absl::UnknownError(
        absl::StrCat("Error downloading public keys from '", url, "'"));
  }
  curl_easy_cleanup(curl);
  return certificate;
}
absl::StatusOr<ListPublicKeysResponse> ParseKeyJson(
    absl::string_view content,
    privacy_sandbox::public_key_service::ExecutionEnvironment
        execution_environment) {
  ListPublicKeysResponse resp;
  HATS_RETURN_IF_ERROR(
      google::protobuf::util::JsonStringToMessage(content, &resp))
      .PrependWith(
          "Failed to parse public keys from upstream json with status: ");
  for (auto& public_key : *resp.mutable_public_keys()) {
    public_key.set_execution_environment(execution_environment);
  }
  return resp;
}
}  // namespace

grpc::Status PublicKeyServer::ListPublicKeys(
    grpc::ServerContext* context, const google::protobuf::Empty* request,
    ListPublicKeysResponse* response) {
  absl::StatusOr<std::string> aws_public_key;
  absl::StatusOr<std::string> gcp_public_key;
  absl::StatusOr<std::vector<privacy_sandbox::key_manager::PerOriginPublicKey>>
      onprem_public_key;
  std::thread aws_download([&]() {
    aws_public_key = DownloadPublicKeys(options_.aws_key_endpoint);
  });
  std::thread gcp_download([&]() {
    gcp_public_key = DownloadPublicKeys(options_.gcp_key_endpoint);
  });
  std::thread onprem_download(
      [&]() { onprem_public_key = fetcher_->GetLatestPublicKeys(); });
  aws_download.join();
  gcp_download.join();
  onprem_download.join();
  // Not simple to do threads + multiple status checks with the macros
  if (!aws_public_key.ok() || !gcp_public_key.ok() || !onprem_public_key.ok()) {
    return grpc::Status(
        grpc::StatusCode::UNAVAILABLE,
        absl::StrCat("failed to fetch some public keys from upstream: AWS: ",
                     aws_public_key.status(), " GCP: ", gcp_public_key.status(),
                     " ONPREM: ", onprem_public_key.status()));
  }

  // Upstream breaks the json format assumption and therefore it's a severe
  // issue.
  HATS_ASSIGN_OR_RETURN(
      ListPublicKeysResponse aws_keys,
      ParseKeyJson(*aws_public_key, EXECUTION_ENVIRONMENT_AWS),
      _.PrependWith("Failed to parse AWS json with error: ")
          .With(status_macro::FromAbslStatus));
  HATS_ASSIGN_OR_RETURN(
      ListPublicKeysResponse gcp_keys,
      ParseKeyJson(*gcp_public_key, EXECUTION_ENVIRONMENT_GCP),
      _.PrependWith("Failed to parse GCP json with error: ")
          .With(status_macro::FromAbslStatus));

  (*response->mutable_public_keys())
      .Add(aws_keys.public_keys().begin(), aws_keys.public_keys().end());
  (*response->mutable_public_keys())
      .Add(gcp_keys.public_keys().begin(), gcp_keys.public_keys().end());
  for (const privacy_sandbox::key_manager::PerOriginPublicKey& key :
       (*onprem_public_key)) {
    PublicKey* onprem_key = response->add_public_keys();
    // Example existing key ID format:
    // 7F00000000000000
    // The existing keys are stored as HEX string in the database as STRING(50).
    onprem_key->set_key_id(absl::StrCat(absl::Hex(key.key_id)));
    // Example existing public key format:
    // The existing public keys are stored in non websafe base64 format.
    // The onprem keys are stored in HEX format
    // Therefore, we should do the conversion.
    std::string public_key_bytes;
    if (!absl::HexStringToBytes(key.public_key, &public_key_bytes))
      return grpc::Status(
          grpc::StatusCode::INTERNAL,
          "failed to convert onprem public key from hex to bytes");
    std::string public_key_base64_encoded =
        absl::Base64Escape(public_key_bytes);
    onprem_key->set_public_key(public_key_base64_encoded);
    onprem_key->set_adtech_origin(key.origin);
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
    std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher> fetcher,
    google::cloud::storage::Client bucket_client)
    : options_(options),
      fetcher_(std::move(fetcher)),
      bucket_client_(bucket_client) {}

void CreateAndStartPublicKeyServer(
    const PublicKeyServerOptions& options,
    std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher> fetcher) {
  // CURL global init cannot be called in parallel. We force the call here to
  // prevent curl_easy_init() function from calling this function in separate
  // thread.
  curl_global_init(CURL_GLOBAL_SSL);
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
}  // namespace privacy_sandbox::public_key_service
