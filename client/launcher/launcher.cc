// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "client/launcher/launcher.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/vm_sockets.h>

#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "client/launcher/launcher-server.h"
#include "client/launcher/logs-service.h"
#include "client/launcher/qemu.h"
#include "client/proto/launcher_config.pb.h"
#include "external/google_privacysandbox_servers_common/src/parc/servers/local/parameters.h"
#include "external/google_privacysandbox_servers_common/src/parc/servers/local/parc_server.h"
#include "grpcpp/channel.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "libarchive/archive.h"
#include "libarchive/archive_entry.h"
#include "src/core/lib/iomgr/socket_mutator.h"

namespace privacy_sandbox::client {

namespace {
// The size of gRPC chunk used for orchestrator service to send the blob. Might
// be tunable such that it's more performant.
constexpr size_t kMaxGrpcResponseSize = 3 * 1024 * 1024;
constexpr absl::string_view kKernelBinary = "kernel_bin";
constexpr absl::string_view kSystemImageTarXz = "system.tar.xz";
constexpr absl::string_view kStage0Binary = "stage0_bin";
constexpr absl::string_view kInitRdCpioXz = "initrd.cpio.xz";

absl::Status UntarOneFile(archive* reader, archive* writer) {
  if (reader == nullptr || writer == nullptr) {
    return absl::InternalError("null archive reader or writer is not allowed");
  }
  int ret_code;
  const void* buff;
  size_t size;
  int64_t offset;
  for (;;) {
    ret_code = archive_read_data_block(reader, &buff, &size, &offset);
    if (ret_code == ARCHIVE_EOF) return absl::OkStatus();
    if (ret_code != ARCHIVE_OK)
      return absl::InternalError(
          absl::StrCat("failed to read datablock from archive, error: ",
                       archive_error_string(reader)));
    if (int ret_code = archive_write_data_block(writer, buff, size, offset);
        ret_code != ARCHIVE_OK)
      return absl::InternalError(absl::StrCat(
          "failed to write datablock, error: ", archive_error_string(writer)));
  }

  return absl::OkStatus();
}

absl::Status UntarHatsBundle(archive* reader, archive* writer,
                             absl::string_view tar_file,
                             absl::string_view target_folder) {
  if (reader == nullptr || writer == nullptr) {
    return absl::InternalError("null archive reader or writer is not allowed");
  }
  if (int ret_code = archive_read_open_filename(reader, tar_file.data(),
                                                /*block_size=*/10240);
      ret_code != 0)
    return absl::InternalError(
        absl::StrCat("failed to open hats system bundle tar with error: ",
                     archive_error_string(reader)));

  archive_entry* entry;
  for (;;) {
    int ret_code = archive_read_next_header(reader, &entry);
    if (ret_code == ARCHIVE_EOF) break;
    if (ret_code != ARCHIVE_OK)
      return absl::InternalError(
          absl::StrCat("failed to iterate to next archive entry, error: ",
                       archive_error_string(reader)));

    // redirect to appropriate location.
    absl::string_view path(archive_entry_pathname(entry));
    std::string target_output;
    if (absl::EndsWith(path, kInitRdCpioXz)) {
      target_output = absl::StrCat(target_folder, "/", kInitRdCpioXz);
    } else if (absl::EndsWith(path, kStage0Binary)) {
      target_output = absl::StrCat(target_folder, "/", kStage0Binary);
    } else if (absl::EndsWith(path, kSystemImageTarXz)) {
      target_output = absl::StrCat(target_folder, "/", kSystemImageTarXz);
    } else if (absl::EndsWith(path, kKernelBinary)) {
      target_output = absl::StrCat(target_folder, "/", kKernelBinary);
    } else {
      // No untar happens for unexpected file.
      LOG(INFO) << "ignoring unrelated file: " << path;
      continue;
    }
    archive_entry_set_pathname(entry, target_output.c_str());
    if (int ret_code = archive_write_header(writer, entry);
        ret_code != ARCHIVE_OK)
      return absl::InternalError(
          absl::StrCat("failed to untar on header write error: ",
                       archive_error_string(writer)));

    absl::Status status = UntarOneFile(reader, writer);
    if (!status.ok()) return status;
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
CreateParcServer(const ParcConfig& config) {
  // 8 MiB.
  constexpr int64_t kBlobChunkSizeMax = 8 * 1 << 20;
  const std::string blob_storage_root = std::filesystem::path(
      static_cast<std::string>(config.blob_storage_root()));
  const std::string parameters_file_path = std::filesystem::path(
      static_cast<std::string>(config.parameters_file_path()));
  absl::StatusOr<privacysandbox::parc::local::v0::Parameters> parameters =
      privacysandbox::parc::local::v0::Parameters::Create(parameters_file_path);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return std::make_unique<privacysandbox::parc::local::v0::ParcServer>(
      std::move(parameters).value(), blob_storage_root, kBlobChunkSizeMax);
}

absl::StatusOr<Qemu::Options> GetQemuOptions(
    const LauncherExtDeps& deps, const LauncherConfig& launcher_config) {
  CVMConfig cvm_config = launcher_config.cvm_config();
  Qemu::Options option = {
      .vmm_binary = cvm_config.vmm_binary(),
      .stage0_binary = deps.stage0_binary_path.data(),
      .kernel = deps.kernel_binary_path.data(),
      .initrd = deps.initrd_cpio_xz_path.data(),
      .memory_size = absl::StrFormat("%dk", cvm_config.ram_size_kb()),
      .num_cpus = cvm_config.num_cpus(),
      .ramdrive_size = cvm_config.ramdrive_size_kb(),
  };

  if (cvm_config.has_virtio_guest_cid())
    option.virtio_guest_cid = cvm_config.virtio_guest_cid();
  switch (cvm_config.cvm_type()) {
    case CVMTYPE_DEFAULT:
      option.vm_type = Qemu::VmType::kDefault;
      break;
    case CVMTYPE_SEV:
      option.vm_type = Qemu::VmType::kSev;
      break;
    case CVMTYPE_SEVES:
      option.vm_type = Qemu::VmType::kSevEs;
      break;
    case CVMTYPE_SEVSNP:
      option.vm_type = Qemu::VmType::kSevSnp;
      break;
    case CVMTYPE_TDX:
      return absl::UnimplementedError("tdx is not implemented");
    case CVMType_INT_MIN_SENTINEL_DO_NOT_USE_:
    case CVMType_INT_MAX_SENTINEL_DO_NOT_USE_:
      return absl::UnknownError("invalid CVMType");
  }

  if (cvm_config.debug_telnet_port() != 0) {
    option.telnet_port = cvm_config.debug_telnet_port();
  }
  if (cvm_config.network_config().has_inbound_only()) {
    option.network_mode = Qemu::NetworkMode::kRestricted;
    option.host_proxy_port = cvm_config.network_config()
                                 .inbound_only()
                                 .host_enclave_app_proxy_port();
  } else if (cvm_config.network_config().has_inbound_and_outbound()) {
    option.network_mode = Qemu::NetworkMode::kOutboundAllowed;
    option.host_proxy_port = cvm_config.network_config()
                                 .inbound_and_outbound()
                                 .host_enclave_app_proxy_port();
  } else if (cvm_config.network_config().has_virtual_bridge()) {
    option.network_mode = Qemu::NetworkMode::kRoutableIp;
    option.virtual_bridge =
        cvm_config.network_config().virtual_bridge().virtual_bridge_device();
    option.vm_ip_address =
        cvm_config.network_config().virtual_bridge().cvm_ip_addr();
    option.vm_gateway_address =
        cvm_config.network_config().virtual_bridge().cvm_gateway_addr();
  } else {
    return absl::UnimplementedError("unsupported networking config");
  }

  return option;
}

absl::StatusOr<LauncherExtDeps> UnbundleHatsBundle(
    const LauncherConfig& config) {
  char tmp_format[] = "/tmp/hats-XXXXXXX";
  char* tmp_dir = mkdtemp(tmp_format);
  if (tmp_dir == nullptr)
    return absl::InternalError(
        "failed to create temporary folder to hold untarred hats "
        "image bundle");

  LOG(INFO) << "temporary folder generated at " << tmp_dir;
  const std::string hats_system_bundle =
      config.cvm_config().hats_system_bundle();
  LOG(INFO) << "untarring hats system image at " << hats_system_bundle;
  archive* reader;
  reader = archive_read_new();
  archive_read_support_format_tar(reader);
  archive* writer;
  writer = archive_write_disk_new();
  int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM;
  archive_write_disk_set_options(writer, flags);
  absl::Status status =
      UntarHatsBundle(reader, writer, hats_system_bundle, tmp_dir);
  archive_read_close(reader);
  archive_read_free(reader);
  archive_read_close(writer);
  archive_read_free(writer);
  if (!status.ok()) return status;

  LauncherExtDeps ext_deps;
  ext_deps.kernel_binary_path = absl::StrCat(tmp_dir, "/", kKernelBinary);
  ext_deps.oak_system_image_path =
      absl::StrCat(tmp_dir, "/", kSystemImageTarXz);
  ext_deps.stage0_binary_path = absl::StrCat(tmp_dir, "/", kStage0Binary);
  ext_deps.initrd_cpio_xz_path = absl::StrCat(tmp_dir, "/", kInitRdCpioXz);
  return ext_deps;
}

// Use Grpc socket mutator to get the vSock port used by a Grpc server.
// We do not want to choose a port and pass it to Grpc as it might be bound
// to another socket. Grpc offers a way to return the selected port via
// passing a pointer to AddListeningPort(), however, it always returns 1
// for vSock [1]. Furthermore, SO_REUSEPORT does not work with vSock.
// Here we use a socket mutator to get the assigned port.
// [1]
// https://github.com/grpc/grpc/blob/f55bf225da0eafeeebffd507dcb57c625933d105/src/core/lib/address_utils/sockaddr_utils.cc#L371

class GrpcSocketMutator : public grpc_socket_mutator {
 public:
  GrpcSocketMutator() {
    static constexpr grpc_socket_mutator_vtable vt = {
        .compare = [](grpc_socket_mutator* a, grpc_socket_mutator* b) -> int {
          return reinterpret_cast<uintptr_t>(a) -
                 reinterpret_cast<uintptr_t>(b);
        },
        .destroy =
            [](grpc_socket_mutator* mutator) {
              GrpcSocketMutator* self =
                  static_cast<GrpcSocketMutator*>(mutator);
              delete self;
            },
        .mutate_fd_2 =
            [](const grpc_mutate_socket_info* info,
               grpc_socket_mutator* mutator) {
              if (info->usage != GRPC_FD_SERVER_LISTENER_USAGE) {
                return true;
              }
              return static_cast<GrpcSocketMutator*>(mutator)->Mutate(info->fd);
            },
    };
    grpc_socket_mutator_init(this, &vt);
  }

  bool Mutate(int fd) {
    sock_fd_ = fd;
    return true;
  }

  absl::StatusOr<uint32_t> GetPort() const {
    sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(sockaddr_vm);
    if (int r = getsockname(sock_fd_, (struct sockaddr*)&addr, &len); r < 0) {
      return absl::UnknownError(
          absl::StrCat("Failed to get socket name: ", strerror(r)));
    }
    return addr.svm_port;
  }

 private:
  int sock_fd_;
};

class SocketMutatorServerBuilderOption : public grpc::ServerBuilderOption {
 public:
  SocketMutatorServerBuilderOption() {
    grpc_socket_mutator_ = new GrpcSocketMutator();
  }

  void UpdateArguments(grpc::ChannelArguments* args) override {
    args->SetSocketMutator(grpc_socket_mutator_);
  }

  void UpdatePlugins(
      std::vector<std::unique_ptr<grpc::ServerBuilderPlugin>>*) override {}

  const GrpcSocketMutator& GetMutator() const { return *grpc_socket_mutator_; }

 private:
  GrpcSocketMutator* grpc_socket_mutator_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<HatsLauncher>> HatsLauncher::Create(
    const HatsLauncherConfig& config,
    const std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>&
        channel_map) {
  // External dependencies must be satisfied for hats launcher to run.
  absl::StatusOr<LauncherExtDeps> deps = UnbundleHatsBundle(config.config);
  if (!deps.ok()) return deps.status();

  (*deps).container_bundle = config.config.cvm_config().runc_runtime_bundle();

  absl::StatusOr<Qemu::Options> qemu_options =
      GetQemuOptions(*deps, config.config);
  if (!qemu_options.ok()) return qemu_options.status();

  auto launcher_server = std::make_unique<client::LauncherServer>(
      config.tvs_authentication_key_bytes, config.private_key_wrapping_keys,
      channel_map);

  auto launcher_oak_server = std::make_unique<LauncherOakServer>(
      (*deps).oak_system_image_path, (*deps).container_bundle,
      kMaxGrpcResponseSize);
  auto logs_service = std::make_unique<LogsService>();

  grpc::ServerBuilder vsock_builder;
  vsock_builder.RegisterService(launcher_server.get())
      .RegisterService(launcher_oak_server.get())
      .RegisterService(logs_service.get());
  vsock_builder.AddListeningPort(
      absl::StrCat("vsock:", VMADDR_CID_HOST, ":", VMADDR_PORT_ANY),
      grpc::InsecureServerCredentials());

  auto socket_mutator_server_builder_options =
      std::make_unique<SocketMutatorServerBuilderOption>();
  const GrpcSocketMutator& grpc_socket_mutator =
      socket_mutator_server_builder_options->GetMutator();
  vsock_builder.SetOption(std::move(socket_mutator_server_builder_options));
  std::unique_ptr<grpc::Server> vsock_server = vsock_builder.BuildAndStart();
  absl::StatusOr<uint32_t> vsock_port = grpc_socket_mutator.GetPort();
  if (!vsock_port.ok()) return vsock_port.status();
  qemu_options->launcher_vsock_port = *vsock_port;

  // parc and tcp servers are nullptr when they are not specified.
  std::unique_ptr<privacysandbox::parc::local::v0::ParcServer> parc_server;
  std::unique_ptr<grpc::Server> tcp_server;

  if (config.config.has_parc_config()) {
    absl::StatusOr<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
        parc_server_or = CreateParcServer(config.config.parc_config());
    if (!parc_server_or.ok()) return parc_server_or.status();
    parc_server = *std::move(parc_server_or);
    grpc::ServerBuilder builder;
    builder.RegisterService(parc_server.get());
    int port;
    // Pass wildcard port i.e 0 so that grpc chooses a port for us.
    builder.AddListeningPort("0.0.0.0:0", grpc::InsecureServerCredentials(),
                             &port);
    tcp_server = builder.BuildAndStart();
    qemu_options->workload_service_port = port;
    LOG(INFO) << "Server listening on 'vsock:" << VMADDR_CID_HOST << ":"
              << *vsock_port << "' and '0.0.0.0:" << port << "'";
  } else {
    LOG(INFO) << "Server listening on 'vsock:" << VMADDR_CID_HOST << ":"
              << *vsock_port << "'";
  }

  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create(*qemu_options);
  if (!qemu.ok()) return qemu.status();
  (*deps).vmm_binary_path = (*qemu_options).vmm_binary;

  return absl::WrapUnique(new HatsLauncher(
      *std::move(deps), *std::move(qemu), std::move(launcher_oak_server),
      std::move(launcher_server), std::move(logs_service),
      std::move(vsock_server), std::move(parc_server), std::move(tcp_server)));
}

absl::Status HatsLauncher::Start(absl::string_view qemu_log_filename) {
  absl::MutexLock lock(&mu_);
  if (started_) {
    return absl::UnknownError(
        "HatsLauncher is only expected to be started once even if shutdown.");
  }
  started_ = true;

  LOG(INFO) << "Qemu command:" << qemu_->GetCommand();
  if (absl::Status status = qemu_->Start(qemu_log_filename); !status.ok())
    return status;
  LOG(INFO) << "Qemu LogFilename:" << qemu_->LogFilename();
  return absl::OkStatus();
}

void HatsLauncher::Wait() {
  {
    absl::MutexLock lock(&mu_);
    if (!started_) {
      return;
    }
  }
  qemu_->Wait();
}

absl::StatusOr<std::shared_ptr<grpc::Channel>>
HatsLauncher::VsockChannelForTest() {
  absl::MutexLock lock(&mu_);
  if (!started_) return absl::UnknownError("HatsLauncher is not started yet");
  return vsock_server_->InProcessChannel(grpc::ChannelArguments());
}

absl::StatusOr<std::shared_ptr<grpc::Channel>>
HatsLauncher::TcpChannelForTest() {
  absl::MutexLock lock(&mu_);
  if (!started_) return absl::UnknownError("HatsLauncher is not started yet");
  if (tcp_server_ == nullptr)
    return absl::NotFoundError("No TCP server is found.");
  return tcp_server_->InProcessChannel(grpc::ChannelArguments());
}

void HatsLauncher::Shutdown() {
  absl::MutexLock lock(&mu_);
  // Qemu object and gRPC servers have internal Mutex lock.
  qemu_->Shutdown();
  vsock_server_->Shutdown();
  if (tcp_server_ != nullptr) tcp_server_->Shutdown();
}

void HatsLauncher::WaitUntilReady() {
  while (true) {
    {
      absl::MutexLock lock(&mu_);
      if (started_) {
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

HatsLauncher::HatsLauncher(
    LauncherExtDeps deps, absl::Nonnull<std::unique_ptr<Qemu>> qemu,
    absl::Nonnull<std::unique_ptr<LauncherOakServer>> launcher_oak_server,
    absl::Nonnull<std::unique_ptr<LauncherServer>> launcher_server,
    absl::Nonnull<std::unique_ptr<LogsService>> logs_service,
    absl::Nonnull<std::unique_ptr<grpc::Server>> vsock_server,
    absl::Nullable<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
        parc_server,
    absl::Nullable<std::unique_ptr<grpc::Server>> tcp_server)
    : deps_(std::move(deps)),
      qemu_(std::move(qemu)),
      launcher_oak_server_(std::move(launcher_oak_server)),
      launcher_server_(std::move(launcher_server)),
      logs_service_(std::move(logs_service)),
      vsock_server_(std::move(vsock_server)),
      parc_server_(std::move(parc_server)),
      tcp_server_(std::move(tcp_server)) {}

}  // namespace privacy_sandbox::client
