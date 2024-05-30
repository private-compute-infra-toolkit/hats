#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "tvs/trusted_tvs/src/lib.rs.h"
#include "tvs/untrusted_tvs/tvs-server.h"

ABSL_FLAG(int, port, 8081, "Port TVS server listens to.");
// TODO(alwabel): implement a better key provisioning.
ABSL_FLAG(std::string, tvs_private_key, "",
          "Private key for NK-Noise handshake protocol.");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  LOG(INFO) << "Starting TVS server on port " << absl::GetFlag(FLAGS_port);
  privacy_sandbox::tvs::CreateAndStartTvsServer(
      privacy_sandbox::tvs::TvsServerOptions{
          .port = absl::GetFlag(FLAGS_port),
          .tvs_private_key = absl::GetFlag(FLAGS_tvs_private_key),
      });
  return 0;
}
