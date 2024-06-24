#ifndef HATS_TVS_CREDENTIALS_CREDENTIALS_H_
#define HATS_TVS_CREDENTIALS_CREDENTIALS_H_

#include "grpcpp/create_channel.h"

namespace privacy_sandbox::tvs {

// Utility to returns credentials to be used in Grpc channel.
std::shared_ptr<grpc::Channel> CreateGrpcChannel(const std::string& target,
                                                 bool use_tls);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_CREDENTIALS_CREDENTIALS_H_
