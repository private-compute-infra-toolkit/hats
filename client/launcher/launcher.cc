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
#include "client/proto/launcher_config.pb.h"
#include "libarchive/include/archive.h"
#include "libarchive/include/archive_entry.h"
namespace privacy_sandbox::client {
namespace {
constexpr absl::string_view kKernelBinary = "kernel_bin";
constexpr absl::string_view kSystemImageTarXz = "system.tar.xz";
constexpr absl::string_view kStage0Binary = "stage0_bin";
constexpr absl::string_view kInitRdCPIOXz = "initrd.cpio.xz";

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
    if (absl::EndsWith(path, kInitRdCPIOXz)) {
      target_output = absl::StrCat(target_folder, "/", kInitRdCPIOXz);
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

  return absl::WrapUnique(new HatsLauncher(std::string(tmp_dir)));
}

HatsLauncher::HatsLauncher(std::string hats_bundle_dir)
    : kernel_binary_path_(absl::StrCat(hats_bundle_dir, "/", kKernelBinary)),
      system_image_tar_xz_path_(
          absl::StrCat(hats_bundle_dir, "/", kSystemImageTarXz)),
      stage0_binary_path_(absl::StrCat(hats_bundle_dir, "/", kStage0Binary)),
      initrd_cpio_xz_path_(absl::StrCat(hats_bundle_dir, "/", kInitRdCPIOXz)) {}
std::string HatsLauncher::GetKernelBinaryPath() { return kernel_binary_path_; }
std::string HatsLauncher::GetSystemImageTarXzPath() {
  return system_image_tar_xz_path_;
}
std::string HatsLauncher::GetStage0BinaryPath() { return stage0_binary_path_; }
std::string HatsLauncher::GetInitrdCpioXzPath() { return initrd_cpio_xz_path_; }
}  // namespace privacy_sandbox::client
