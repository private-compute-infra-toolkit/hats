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

#ifndef HATS_PUBLIC_KEY_PUBLIC_KEY_SERVER_H_
#define HATS_PUBLIC_KEY_PUBLIC_KEY_SERVER_H_

#include <memory>
#include <string>

#include "google/cloud/storage/client.h"
#include "google/protobuf/empty.pb.h"
#include "key_manager/public-key-fetcher.h"
#include "public_key/proto/public_key_service.grpc.pb.h"
#include "public_key/proto/public_key_service.pb.h"

namespace pcit::public_key_service {

struct PublicKeyServerOptions {
  int port;
  // Bucket storing the public key json file distributed to all clients.
  std::string gcp_cloud_bucket_name;
};

class PublicKeyServer final : public PublicKeyService::Service {
 public:
  PublicKeyServer() = delete;
  PublicKeyServer(const PublicKeyServerOptions& options,
                  std::unique_ptr<pcit::key_manager::PublicKeyFetcher> fetcher,
                  google::cloud::storage::Client bucket_client);
  grpc::Status ListPublicKeys(grpc::ServerContext* context,
                              const google::protobuf::Empty* request,
                              ListPublicKeysResponse* response) override;
  grpc::Status UpdateCloudBucket(grpc::ServerContext* context,
                                 const google::protobuf::Empty* request,
                                 google::protobuf::Empty* response) override;

 private:
  const PublicKeyServerOptions options_;
  const std::unique_ptr<pcit::key_manager::PublicKeyFetcher> fetcher_;
  google::cloud::storage::Client bucket_client_;
};

void CreateAndStartPublicKeyServer(
    const PublicKeyServerOptions& options,
    std::unique_ptr<pcit::key_manager::PublicKeyFetcher> fetcher);
}  // namespace pcit::public_key_service
#endif  // HATS_PUBLIC_KEY_PUBLIC_KEY_SERVER_H_
