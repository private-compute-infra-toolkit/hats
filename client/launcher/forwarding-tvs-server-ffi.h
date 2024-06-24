#ifndef HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_
#define HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_

#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "rust/cxx.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

void CreateAndStartForwardingTvsServer(uint32_t port, rust::Str target,
                                       bool use_tls);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_FFI_
