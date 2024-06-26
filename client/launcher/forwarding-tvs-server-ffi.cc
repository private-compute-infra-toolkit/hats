#include "client/launcher/forwarding-tvs-server-ffi.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "client/launcher/forwarding-tvs-server.h"
#include "grpcpp/channel.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "rust/cxx.h"
#include "tvs/credentials/credentials.h"

namespace privacy_sandbox::tvs {

void CreateAndStartForwardingTvsServer(uint32_t port, bool use_tls,
                                       rust::Str target,
                                       rust::Str access_token) {
  // Create a server only once and do nothing if the function is called again.
  // We wrap the code in a lambda to ensure safe initialization.
  // We do this because we are release the server pointer and we don't want to
  // have memory leaks.
  static absl::Status status = [&] {
    const std::string server_address = absl::StrCat("0.0.0.0:", port);
    // This is a string copy, but that is the best we can do with FFI.
    // We can try to map rust::Str to string_view or so.
    absl::StatusOr<std::shared_ptr<grpc::Channel>> channel =
        privacy_sandbox::tvs::CreateGrpcChannel({
            .use_tls = use_tls,
            .target = static_cast<std::string>(target),
            .access_token = static_cast<std::string>(access_token),
        });

    if (!channel.ok()) {
      return channel.status();
    }

    static auto forwarding_tvs_server =
        std::make_unique<ForwardingTvsServer>(std::move(channel).value());
    static std::unique_ptr<grpc::Server> server =
        grpc::ServerBuilder()
            .AddListeningPort(server_address, grpc::InsecureServerCredentials())
            .RegisterService(forwarding_tvs_server.get())
            .BuildAndStart();
    LOG(INFO) << "Server listening on " << server_address;
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

}  // namespace privacy_sandbox::tvs
