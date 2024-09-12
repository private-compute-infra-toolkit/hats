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
      .pci_passthrough = cvm_config.pci_passthrough(),
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
  option.launcher_service_port = launcher_config.launcher_service_port();
  if (cvm_config.network_config().has_inbound_only()) {
    option.network_mode = Qemu::NetworkMode::kRestricted;
    option.host_proxy_port = cvm_config.network_config()
                                 .inbound_only()
                                 .host_enclave_app_proxy_port();
    option.host_orchestrator_proxy_port = cvm_config.network_config()
                                              .inbound_only()
                                              .host_orchestrator_proxy_port();
  } else if (cvm_config.network_config().has_inbound_and_outbound()) {
    option.network_mode = Qemu::NetworkMode::kOutboundAllowed;
    option.host_proxy_port = cvm_config.network_config()
                                 .inbound_and_outbound()
                                 .host_enclave_app_proxy_port();
    option.host_orchestrator_proxy_port = cvm_config.network_config()
                                              .inbound_and_outbound()
                                              .host_orchestrator_proxy_port();
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
}  // namespace

absl::StatusOr<std::unique_ptr<HatsLauncher>> HatsLauncher::Create(
    const HatsLauncherConfig& config,
    const std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>&
        channel_map) {
  // External dependencies must be satisfied for hats launcher to run.
  absl::StatusOr<LauncherExtDeps> deps = UnbundleHatsBundle(config.config);
  if (!deps.ok()) return deps.status();

  (*deps).container_bundle = config.config.cvm_config().runc_runtime_bundle();

  absl::StatusOr<Qemu::Options> option = GetQemuOptions(*deps, config.config);
  if (!option.ok()) return option.status();

  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create(*option);
  if (!qemu.ok()) return qemu.status();
  (*deps).vmm_binary_path = (*option).vmm_binary;

  auto launcher_server = std::make_unique<client::LauncherServer>(
      config.tvs_authentication_key_bytes, channel_map);

  auto launcher_oak_server = std::make_unique<LauncherOakServer>(
      (*deps).oak_system_image_path, (*deps).container_bundle,
      kMaxGrpcResponseSize);

  // PARC server will be NULL when it's not specified.
  absl::Nullable<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
      parc_server_nullable = nullptr;
  if (config.config.has_parc_config()) {
    absl::StatusOr<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
        parc_server = CreateParcServer(config.config.parc_config());
    if (!parc_server.ok()) return parc_server.status();
    parc_server_nullable = *std::move(parc_server);
  }

  std::string addr_uri =
      absl::StrFormat("0.0.0.0:%d", config.config.launcher_service_port());
  std::string vsock_uri = absl::StrFormat(
      "vsock:%d:%d", VMADDR_CID_HOST, config.config.launcher_service_port());

  return absl::WrapUnique(new HatsLauncher(
      addr_uri, vsock_uri, *std::move(deps), *std::move(qemu),
      std::move(launcher_oak_server), std::move(launcher_server),
      std::move(parc_server_nullable)));
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
  grpc::ServerBuilder builder;
  // All gRPC servers are owned by the HatsLauncher object.
  builder.RegisterService(launcher_server_.get())
      .RegisterService(launcher_oak_server_.get())
      .RegisterService(&logs_service_);
  builder.AddListeningPort(addr_uri_, grpc::InsecureServerCredentials());

  if (parc_server_ != nullptr) {
    LOG(INFO)
        << "PARC server is enabled ( configured by parc_config existence )";
    builder.RegisterService(parc_server_.get());
  }

  // Only Oak services are required for stage 1.
  grpc::ServerBuilder vsock_builder;
  vsock_builder.RegisterService(launcher_oak_server_.get());
  vsock_builder.RegisterService(&logs_service_);
  vsock_builder.AddListeningPort(vsock_uri_, grpc::InsecureServerCredentials());

  vsock_server_ = vsock_builder.BuildAndStart();
  tcp_server_ = builder.BuildAndStart();
  LOG(INFO) << "Server listening on '" << addr_uri_ << "' and '" << vsock_uri_
            << "'";

  // blocking
  return absl::OkStatus();
}

void HatsLauncher::Wait() {
  {
    absl::MutexLock lock(&mu_);
    if (!started_) {
      return;
    }
  }

  tcp_server_->Wait();
  vsock_server_->Wait();
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
  return tcp_server_->InProcessChannel(grpc::ChannelArguments());
}

void HatsLauncher::Shutdown() {
  absl::MutexLock lock(&mu_);
  // Qemu object and gRPC servers have internal Mutex lock.
  qemu_->Shutdown();
  tcp_server_->Shutdown();
  vsock_server_->Shutdown();
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
    absl::string_view addr_uri, absl::string_view vsock_uri,
    LauncherExtDeps deps, absl::Nonnull<std::unique_ptr<Qemu>> qemu,
    absl::Nonnull<std::unique_ptr<LauncherOakServer>> launcher_oak_server,
    absl::Nonnull<std::unique_ptr<LauncherServer>> launcher_server,
    absl::Nullable<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
        parc_server)
    : addr_uri_(addr_uri),
      vsock_uri_(vsock_uri),
      deps_(std::move(deps)),
      qemu_(std::move(qemu)),
      launcher_server_(std::move(launcher_server)),
      launcher_oak_server_(std::move(launcher_oak_server)),
      parc_server_(std::move(parc_server)) {}

}  // namespace privacy_sandbox::client
