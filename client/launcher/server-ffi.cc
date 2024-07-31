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

#include "client/launcher/server-ffi.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "client/launcher/forwarding-tvs-server.h"
#include "external/google_privacysandbox_servers_common/src/parc/servers/local/parameters.h"
#include "external/google_privacysandbox_servers_common/src/parc/servers/local/parc_server.h"
#include "grpcpp/channel.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "rust/cxx.h"
#include "tvs/credentials/credentials.h"

namespace privacy_sandbox::launcher {

namespace {

absl::StatusOr<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
CreateParcServer(const LauncherServerOptions& options) {
  // 8 MiB.
  constexpr int64_t kBlobChunkSizeMax = 8 * 1 << 20;
  const std::filesystem::path blob_storage_root = std::filesystem::path(
      static_cast<std::string>(options.parc_blobstore_root));
  const std::filesystem::path parameters_file_path = std::filesystem::path(
      static_cast<std::string>(options.parc_parameters_file));
  absl::StatusOr<privacysandbox::parc::local::v0::Parameters> parameters =
      privacysandbox::parc::local::v0::Parameters::Create(parameters_file_path);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return std::make_unique<privacysandbox::parc::local::v0::ParcServer>(
      std::move(parameters).value(), blob_storage_root, kBlobChunkSizeMax);
}

}  // namespace

void CreateAndStartServers(const LauncherServerOptions& options) {
  // Create a server only once and do nothing if the function is called again.
  // We wrap the code in a lambda to ensure safe initialization.
  // We do this because we are release the server pointer and we don't want to
  // have memory leaks.
  static absl::Status status = [&] {
    const std::string server_address = absl::StrCat("0.0.0.0:", options.port);
    // This is a string copy, but that is the best we can do with FFI.
    // We can try to map rust::Str to string_view or so.
    absl::StatusOr<std::shared_ptr<grpc::Channel>> channel =
        privacy_sandbox::tvs::CreateGrpcChannel({
            .use_tls = options.forwarding_use_tls,
            .target = static_cast<std::string>(options.forwarding_target),
            .access_token =
                static_cast<std::string>(options.forwarding_access_token),
        });

    if (!channel.ok()) {
      return channel.status();
    }

    auto forwarding_tvs_server =
        std::make_unique<tvs::ForwardingTvsServer>(std::move(channel).value());
    grpc::ServerBuilder server_builder;
    server_builder
        .AddListeningPort(server_address, grpc::InsecureServerCredentials())
        .RegisterService(forwarding_tvs_server.get());

    LOG(INFO) << "Server listening on " << server_address;
    if (options.enable_parc) {
      absl::StatusOr<
          std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
          parc_server = CreateParcServer(options);
      if (!parc_server.ok()) {
        return parc_server.status();
      }
      server_builder.RegisterService(parc_server->get());
      // Intentionally release the pointer, read the comment below.
      parc_server->release();
    }

    std::unique_ptr<grpc::Server> server = server_builder.BuildAndStart();
    // Intentionally release the unique pointer so that it doesn't get destroyed
    // after the function returns. FFI doesn't allow returning objects defined
    // in C++, only unique pointers are allowed. However, in async rust unique
    // pointer are not allowed since pointer cannot be sent safely between
    // threads.
    server.release();
    forwarding_tvs_server.release();
    return absl::OkStatus();
  }();

  if (!status.ok()) {
    throw std::invalid_argument(
        absl::StrCat("Error creating GRPC channel: ", status));
  }
}

}  // namespace privacy_sandbox::launcher
