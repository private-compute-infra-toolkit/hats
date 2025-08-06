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

#include "client/sdk/hats_orchestrator_client.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "external/oak/cc/containers/sdk/common.h"
#include "grpcpp/channel.h"
#include "status_macro/status_macros.h"

namespace pcit::server_common {

HatsOrchestratorClient::HatsOrchestratorClient()
    : hats_stub_(HatsOrchestrator::NewStub(
          grpc::CreateChannel(oak::containers::sdk::kOrchestratorSocket,
                              grpc::InsecureChannelCredentials()))) {}

HatsOrchestratorClient::HatsOrchestratorClient(
    std::shared_ptr<grpc::Channel> channel)
    : hats_stub_(HatsOrchestrator::NewStub(channel)) {}

absl::StatusOr<std::vector<Key>> HatsOrchestratorClient::GetKeys() const {
  grpc::ClientContext context;
  context.set_authority(oak::containers::sdk::kContextAuthority);
  GetKeysResponse response;
  HATS_RETURN_IF_ERROR(hats_stub_->GetKeys(&context, {}, &response));
  std::vector<Key> keys;
  // Non-const to allow effective moving.
  for (Key& key : *response.mutable_keys()) {
    keys.push_back(std::move(key));
  }
  return keys;
}

}  // namespace pcit::server_common
