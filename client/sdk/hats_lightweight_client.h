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

#ifndef HATS_CLIENT_SDK_HATS_LIGHTWEIGHT_CLIENT_H_
#define HATS_CLIENT_SDK_HATS_LIGHTWEIGHT_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "client/proto/orchestrator.grpc.pb.h"
#include "client/proto/orchestrator.pb.h"
#include "grpcpp/channel.h"

namespace privacy_sandbox::client {

// Client to the orchestrator to be used by the workload to obtain the HPKE key.
class HatsLightweightClient final {
 public:
  HatsLightweightClient();
  HatsLightweightClient(std::shared_ptr<grpc::Channel> channel);

  absl::StatusOr<std::vector<Key>> GetKeys() const;

 private:
  std::unique_ptr<HatsOrchestrator::Stub> hats_stub_;
};

}  // namespace privacy_sandbox::client
#endif  // HATS_CLIENT_SDK_HATS_LIGHTWEIGHT_CLIENT_H_
