#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_FLAG(std::string, tvs_address, "localhost:8081", "TVS server address.");
ABSL_FLAG(std::string, tvs_public_key, "",
          "TVS public key in hex format e.g. deadbeef");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");
ABSL_FLAG(
    std::string, verify_report_request_file, "",
    "File containing a VerifyReportRequest to be sent to TVS for validation");

namespace {

std::shared_ptr<grpc::Channel> CreateGrpcChannel(const std::string& target,
                                                 bool use_tls) {
  if (use_tls) {
    return grpc::CreateChannel(target, grpc::SslCredentials(/*options=*/{}));
  } else {
    return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  const std::string verify_report_request_file =
      absl::GetFlag(FLAGS_verify_report_request_file);
  if (verify_report_request_file.empty()) {
    LOG(ERROR) << "--verify_report_request_file cannot be empty.";
    return 1;
  }
  std::ifstream if_stream(verify_report_request_file);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  privacy_sandbox::tvs::VerifyReportRequest verify_report_request;
  if (!google::protobuf::TextFormat::Parse(&istream, &verify_report_request)) {
    LOG(ERROR) << "Failed to parse " << verify_report_request_file;
    return 1;
  }

  const std::string tvs_address = absl::GetFlag(FLAGS_tvs_address);
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
      (*tvs_client)->VerifyReportAndGetToken(verify_report_request);
  if (!token.ok()) {
    std::cout << "TVS rejected the report: " << token.status() << std::endl;
  }
  std::cout << "Token: " << *token << std::endl;
  return 0;
}
