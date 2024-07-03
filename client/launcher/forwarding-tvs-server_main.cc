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

#include <grpcpp/channel.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "client/launcher/forwarding-tvs-server.h"
#include "tvs/credentials/credentials.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
ABSL_FLAG(std::string, remote_address, "", "");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");
ABSL_FLAG(std::string, access_token, "",
          "Access token to pass in the GRPC request. TLS need to be enabled");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  if (!absl::GetFlag(FLAGS_access_token).empty() &&
      !absl::GetFlag(FLAGS_use_tls)) {
    LOG(ERROR) << "TLS need to be enabled when passing access token.";
    return 1;
  }

  absl::StatusOr<std::shared_ptr<grpc::Channel>> channel =
      privacy_sandbox::tvs::CreateGrpcChannel({
          .use_tls = absl::GetFlag(FLAGS_use_tls),
          .target = absl::GetFlag(FLAGS_remote_address),
          .access_token = absl::GetFlag(FLAGS_access_token),
      });
  if (!channel.ok()) {
    LOG(ERROR) << "Error creating GRPC channel: " << channel;
    return 1;
  }

  int port = absl::GetFlag(FLAGS_port);
  LOG(INFO) << "Starting TVS server on port " << port;
  privacy_sandbox::tvs::CreateAndStartForwardingTvsServer(
      port, std::move(channel).value());
  return 0;
}
