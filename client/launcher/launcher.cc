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

#include <string.h>

#include <cstdlib>
#include <fstream>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "client/launcher/qemu.h"
#include "client/proto/launcher_config.pb.h"
#include "libarchive/archive.h"
#include "libarchive/archive_entry.h"

namespace privacy_sandbox::client {
namespace {

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

}  // namespace

absl::StatusOr<Qemu::Options> HatsLauncher::GetQemuOptions(
    absl::string_view kernel_binary_path, absl::string_view stage0_binary_path,
    absl::string_view initrd_cpio_xz_path,
    const LauncherConfig& launcher_config) {
  CVMConfig cvm_config = launcher_config.cvm_config();
  Qemu::Options option = {
      .vmm_binary = cvm_config.vmm_binary(),
      .stage0_binary = stage0_binary_path.data(),
      .kernel = kernel_binary_path.data(),
      .initrd = initrd_cpio_xz_path.data(),
      .memory_size = absl::StrFormat("%dk", cvm_config.ram_size_kb()),
      .num_cpus = cvm_config.num_cpus(),
      .ramdrive_size = cvm_config.ramdrive_size_kb(),
      .virtio_guest_cid = cvm_config.virtio_guest_cid(),
      .pci_passthrough = cvm_config.pci_passthrough(),
  };

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

absl::StatusOr<std::unique_ptr<HatsLauncher>> HatsLauncher::Create(
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

  std::string kernel_binary = absl::StrCat(tmp_dir, "/", kKernelBinary);
  std::string system_image = absl::StrCat(tmp_dir, "/", kSystemImageTarXz);
  std::string stage0_binary = absl::StrCat(tmp_dir, "/", kStage0Binary);
  std::string initrd = absl::StrCat(tmp_dir, "/", kInitRdCpioXz);
  absl::StatusOr<Qemu::Options> option = HatsLauncher::GetQemuOptions(
      kernel_binary, stage0_binary, initrd, config);
  if (!option.ok()) return option.status();
  absl::StatusOr<std::unique_ptr<Qemu>> qemu = Qemu::Create(*option);
  if (!qemu.ok()) return qemu.status();
  return absl::WrapUnique(new HatsLauncher(
      kernel_binary, system_image, stage0_binary, initrd, *std::move(qemu)));
}

absl::Status HatsLauncher::Start() {
  LOG(INFO) << "qemu command:" << qemu_->GetCommand();
  LOG(INFO) << "LogFilename:" << qemu_->LogFilename();
  absl::Status qemu_status = qemu_->Start();
  if (!qemu_status.ok()) {
    return qemu_status;
  }
  // Blocking call.
  qemu_->Wait();

  return absl::OkStatus();
}

HatsLauncher::HatsLauncher(std::string kernel_binary_path,
                           std::string system_image_tar_xz_path,
                           std::string stage0_binary_path,
                           std::string initrd_cpio_xz_path,
                           std::unique_ptr<Qemu> qemu)
    : kernel_binary_path_(std::move(kernel_binary_path)),
      system_image_tar_xz_path_(std::move(system_image_tar_xz_path)),
      stage0_binary_path_(std::move(stage0_binary_path)),
      initrd_cpio_xz_path_(std::move(initrd_cpio_xz_path)),
      qemu_(std::move(qemu)) {}
std::string HatsLauncher::GetKernelBinaryPath() { return kernel_binary_path_; }
std::string HatsLauncher::GetSystemImageTarXzPath() {
  return system_image_tar_xz_path_;
}

std::string HatsLauncher::GetStage0BinaryPath() { return stage0_binary_path_; }

std::string HatsLauncher::GetInitrdCpioXzPath() { return initrd_cpio_xz_path_; }

}  // namespace privacy_sandbox::client
