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

#ifndef HATS_CLIENT_TRUSTED_APPLICATION_ENCLAVE_APP_TRUSTED_APPLICATION_H_
#define HATS_CLIENT_TRUSTED_APPLICATION_ENCLAVE_APP_TRUSTED_APPLICATION_H_

#include "client/proto/trusted_service.grpc.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "client/sdk/hats_orchestrator_client.h"

namespace privacy_sandbox::client {

class TrustedApplication final : public TrustedService::Service {
 public:
  TrustedApplication() = default;

  grpc::Status Echo(grpc::ServerContext* context,
                    const EncryptedRequest* request,
                    DecryptedResponse* response) override;

 private:
  privacy_sandbox::server_common::HatsOrchestratorClient
      hats_orchestrator_client_;
};
}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_TRUSTED_APPLICATION_ENCLAVE_APP_TRUSTED_APPLICATION_H_
