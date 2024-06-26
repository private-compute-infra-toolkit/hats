#ifndef HATS_TVS_CREDENTIALS_CREDENTIALS_H_
#define HATS_TVS_CREDENTIALS_CREDENTIALS_H_

#include "grpcpp/create_channel.h"

namespace privacy_sandbox::tvs {

struct CreateGrpcChannelOptions {
  bool use_tls;
  std::string target;
  std::string access_token;
};

// Utility to returns credentials to be used in Grpc channel.
absl::StatusOr<std::shared_ptr<grpc::Channel>> CreateGrpcChannel(
    const CreateGrpcChannelOptions& options);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_CREDENTIALS_CREDENTIALS_H_
