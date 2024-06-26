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
