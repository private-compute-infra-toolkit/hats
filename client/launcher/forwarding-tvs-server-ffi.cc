#include "client/launcher/forwarding-tvs-server-ffi.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "client/launcher/forwarding-tvs-server.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/interceptor.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "rust/cxx.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

void CreateAndStartForwardingTvsServer(uint32_t port, rust::Str target,
                                       bool use_tls) {
  const std::string server_address = absl::StrCat("0.0.0.0:", port);
  // This is a string copy, but that is the best we can do with FFI.
  // We can try to map rust::Str to string_view or so.
  ForwardingTvsServer forwarding_tvs_server(
      CreateGrpcChannel(static_cast<std::string>(target), use_tls));
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(&forwarding_tvs_server)
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();
}

}  // namespace privacy_sandbox::tvs
