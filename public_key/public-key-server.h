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

#include "google/protobuf/empty.pb.h"
#include "key_manager/public-key-fetcher.h"
#include "public_key/proto/public_key_service.grpc.pb.h"
#include "public_key/proto/public_key_service.pb.h"

namespace privacy_sandbox::public_key_service {

struct PublicKeyServerOptions {
  int port;
  std::string aws_key_endpoint;
  std::string gcp_key_endpoint;
};

class PublicKeyServer final : public PublicKeyService::Service {
 public:
  PublicKeyServer() = delete;
  PublicKeyServer(
      const PublicKeyServerOptions& options,
      std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher> fetcher);
  grpc::Status ListPublicKeys(grpc::ServerContext* context,
                              const google::protobuf::Empty* request,
                              ListPublicKeysResponse* response) override;

 private:
  const PublicKeyServerOptions options_;
  const std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher>
      fetcher_;
};

void CreateAndStartPublicKeyServer(
    const PublicKeyServerOptions& options,
    std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher> fetcher);
}  // namespace privacy_sandbox::public_key_service
#endif  // HATS_PUBLIC_KEY_PUBLIC_KEY_SERVER_H_
