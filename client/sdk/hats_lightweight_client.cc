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

#include "client/sdk/hats_lightweight_client.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "status_macro/status_macros.h"

namespace pcit::server_common {

HatsLightweightClient::HatsLightweightClient()
    // UDS socket is the one used by Oak.
    // We are hardcoding it instead of including Oak's header
    // to make this client lightweight so our clients do not need
    // to load all Oak's dependencies.
    : hats_stub_(HatsOrchestrator::NewStub(
          grpc::CreateChannel("unix:/oak_utils/orchestrator_ipc",
                              grpc::InsecureChannelCredentials()))) {}

HatsLightweightClient::HatsLightweightClient(
    std::shared_ptr<grpc::Channel> channel)
    : hats_stub_(HatsOrchestrator::NewStub(channel)) {}

absl::StatusOr<std::vector<Key>> HatsLightweightClient::GetKeys() const {
  grpc::ClientContext context;
  context.set_authority("[::]:0");
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
