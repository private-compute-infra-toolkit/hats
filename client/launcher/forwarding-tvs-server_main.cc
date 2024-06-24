#include <optional>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "client/launcher/forwarding-tvs-server.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "tvs/credentials/credentials.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
ABSL_FLAG(std::string, remote_address, "", "");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  int port = absl::GetFlag(FLAGS_port);
  LOG(INFO) << "Starting TVS server on port " << port;
  privacy_sandbox::tvs::CreateAndStartForwardingTvsServer(
      port,
      privacy_sandbox::tvs::CreateGrpcChannel(
          absl::GetFlag(FLAGS_remote_address), absl::GetFlag(FLAGS_use_tls)));
  return 0;
}
