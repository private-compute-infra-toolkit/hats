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

#include "tvs/credentials/credentials.h"

#include <memory>
#include <string>

#include "grpcpp/create_channel.h"

namespace pcit::tvs {

absl::StatusOr<std::shared_ptr<grpc::Channel>> CreateGrpcChannel(
    const CreateGrpcChannelOptions& options) {
  if (!options.access_token.empty() && !options.use_tls) {
    return absl::FailedPreconditionError(
        "TLS need to be enabled when passing access token");
  }

  if (const std::string access_token = options.access_token;
      !access_token.empty()) {
    return grpc::CreateChannel(options.target,
                               grpc::CompositeChannelCredentials(
                                   grpc::SslCredentials(/*options=*/{}),
                                   grpc::AccessTokenCredentials(access_token)));
  }

  if (options.use_tls) {
    return grpc::CreateChannel(options.target,
                               grpc::SslCredentials(/*options=*/{}));
  }

  return grpc::CreateChannel(options.target,
                             grpc::InsecureChannelCredentials());
}

}  // namespace pcit::tvs
