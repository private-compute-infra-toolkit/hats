#include "tvs/credentials/credentials.h"

namespace privacy_sandbox::tvs {

// TODO(alwabel): add credentials used by GCP IAM.
std::shared_ptr<grpc::Channel> CreateGrpcChannel(const std::string& target,
                                                 bool use_tls) {
  if (use_tls) {
    return grpc::CreateChannel(target, grpc::SslCredentials(/*options=*/{}));
  } else {
    return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
  }
}

}  // namespace privacy_sandbox::tvs
