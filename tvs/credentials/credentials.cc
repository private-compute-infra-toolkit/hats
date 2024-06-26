#include "tvs/credentials/credentials.h"

namespace privacy_sandbox::tvs {

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

}  // namespace privacy_sandbox::tvs
