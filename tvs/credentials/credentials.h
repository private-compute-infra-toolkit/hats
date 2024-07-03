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

#ifndef HATS_TVS_CREDENTIALS_CREDENTIALS_H_
#define HATS_TVS_CREDENTIALS_CREDENTIALS_H_

#include "grpcpp/create_channel.h"

namespace privacy_sandbox::tvs {

struct CreateGrpcChannelOptions {
  bool use_tls;
  std::string target;
  std::string access_token;
};

// Utility to returns credentials to be used in Grpc channel.
absl::StatusOr<std::shared_ptr<grpc::Channel>> CreateGrpcChannel(
    const CreateGrpcChannelOptions& options);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_CREDENTIALS_CREDENTIALS_H_
