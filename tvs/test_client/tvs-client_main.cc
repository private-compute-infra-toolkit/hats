#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_FLAG(std::string, tvs_address, "localhost:8081", "TVS server address.");
ABSL_FLAG(std::string, tvs_public_key, "",
          "TVS public key in hex format e.g. deadbeef");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");

namespace {

std::shared_ptr<grpc::Channel> CreateGrpcChannel(const std::string& target,
                                                 bool use_tls) {
  if (use_tls)
    return grpc::CreateChannel(target, grpc::SslCredentials(/*options=*/{}));
  else
    return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  std::string tvs_address = absl::GetFlag(FLAGS_tvs_address);
  LOG(INFO) << "Creating TVS client to : " << tvs_address;
  absl::StatusOr<std::unique_ptr<privacy_sandbox::tvs::TvsUntrustedClient>>
      tvs_client = privacy_sandbox::tvs::TvsUntrustedClient::CreateClient({
          .tvs_public_key = absl::GetFlag(FLAGS_tvs_public_key),
          .channel =
              CreateGrpcChannel(tvs_address, absl::GetFlag(FLAGS_use_tls)),
      });
  if (!tvs_client.ok()) {
    LOG(ERROR) << "Couldn't create TVS client: " << tvs_client.status();
    return 1;
  }
  absl::StatusOr<std::string> token =
      (*tvs_client)->VerifyReportAndGetToken("verify");
  if (!token.ok()) {
    LOG(ERROR) << "Failed to get token: " << token.status();
  }
  std::cout << "Token: " << *token << std::endl;
  return 0;
}
