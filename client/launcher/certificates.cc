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

#include "client/launcher/certificates.h"

#include <errno.h>
#include <stdint.h>

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "client/launcher/kernel-api.h"
#include "client/launcher/snp-abi.h"
#include "curl/curl.h"
#include "external/psp-sev/file/psp-sev.h"
#include "status_macro/status_macros.h"

namespace privacy_sandbox::client {
namespace {
size_t ResponseHandler(char* contents, size_t byte_size, size_t num_bytes,
                       std::string* output) {
  output->append(contents, byte_size * num_bytes);
  return byte_size * num_bytes;
}

absl::StatusOr<std::string> GetCpuModel(const KernelApiInterface& api) {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  api.Cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
  uint32_t socket = (ebx & uint32_t(0xF0000000)) >> 0x1C;
  uint8_t* eax_bytes = reinterpret_cast<uint8_t*>(&eax);
  uint8_t base_model = (eax_bytes[0] & 0xf0) >> 4;
  uint8_t base_family = (eax_bytes[1] & 0x0f);
  uint8_t ext_model = eax_bytes[2] & 0x0f;
  uint8_t ext_family =
      ((eax_bytes[2] & 0xf0) >> 4) | ((eax_bytes[3] & 0x0f) << 4);
  uint8_t model = (ext_model << 4) | base_model;
  uint8_t family = base_family + ext_family;
  if (family != 0x19) {
    return absl::UnknownError(
        absl::StrFormat("unknown SEV-SNP processor family %d", family));
  }

  std::string cpu_model = "";
  if (model >= 0 && model <= 0xf) {
    cpu_model = "Milan";
  } else if (model >= 0x10 && model <= 0x1f) {
    cpu_model = "Genoa";
  } else if (model >= 0xa0 && model <= 0xaf) {
    if (socket == 0x4 || socket == 0x8) {
      cpu_model =
          "Genoa";  // Actual: 0x4 Bergamo, 0x8 Siena; but using same vcek.
    } else {
      return absl::UnknownError(
          absl::StrFormat("unknown SEV-SNP processor generation model number "
                          "%d socket number %d",
                          model, socket));
    }
  } else {
    return absl::UnknownError(
        absl::StrFormat("unknown SEV-SNP processor model number %d", model));
  }

  return cpu_model;
}

absl::Status SevIoCtl(const KernelApiInterface& api, int sev_fd,
                      uint32_t command, uint64_t data) {
  sev_issue_cmd arg{.cmd = command, .data = data};
  int ret = api.Ioctl(sev_fd, arg);
  if (ret < 0) {
    return absl::UnknownError(absl::StrFormat(
        "failed to issue ioctl SEV_ISSUE_CMD with error: %s", strerror(errno)));
  }

  uint32_t error_code = arg.error;
  if (error_code != SEV_RET_SUCCESS) {
    return absl::UnknownError(
        absl::StrFormat("unknown ioctl SEV_GET_ID2 ret code %d", error_code));
  }

  return absl::OkStatus();
}

absl::StatusOr<snp_tcb_version> GetTcbVersion(const KernelApiInterface& api,
                                              int sev_fd) {
  snp_platform_status_buffer buffer;
  memset(&buffer, 0, sizeof(buffer));
  HATS_RETURN_IF_ERROR(SevIoCtl(api, sev_fd, SNP_PLATFORM_STATUS,
                                reinterpret_cast<uint64_t>(&buffer)));
  // Parse the reported_tcb.
  snp_tcb_version version;
  version.val = buffer.reported_tcb;
  return version;
}

absl::StatusOr<std::string> GetCpuId(const KernelApiInterface& api,
                                     int sev_fd) {
  sev_user_data_get_id buffer;
  memset(&buffer, 0, sizeof(buffer));
  sev_user_data_get_id2 id_buf{.address = reinterpret_cast<uint64_t>(&buffer),
                               .length = sizeof(buffer)};
  HATS_RETURN_IF_ERROR(
      SevIoCtl(api, sev_fd, SEV_GET_ID2, reinterpret_cast<uint64_t>(&id_buf)));

  // buffer.socket1 is of type __u8[64]
  const std::string socket1_bytes(reinterpret_cast<const char*>(buffer.socket1),
                                  64);
  return absl::BytesToHexString(socket1_bytes);
}
}  // namespace

absl::StatusOr<std::string> GetCertificateUrl(const KernelApiInterface& api) {
  HATS_ASSIGN_OR_RETURN(std::string cpu_model, GetCpuModel(api));

  int sev_fd = api.OpenSev();
  if (sev_fd < 0) {
    return absl::UnknownError("failed to open /dev/sev fd with O_RDWR mode");
  }
  // Ensure it always closes
  auto close = [&api, &sev_fd](auto x) {
    api.Close(sev_fd);
    return x;
  };
  HATS_ASSIGN_OR_RETURN(std::string cpu_id, GetCpuId(api, sev_fd), close(_));
  HATS_ASSIGN_OR_RETURN(snp_tcb_version tcb_version, GetTcbVersion(api, sev_fd),
                        close(_));
  api.Close(sev_fd);

  return absl::StrFormat(
      "https://kdsintf.amd.com/vcek/v1/%s/"
      "%s?blSPL=%02d&teeSPL=%02d&snpSPL=%02d&ucodeSPL=%02d",
      cpu_model, cpu_id, tcb_version.f.boot_loader, tcb_version.f.tee,
      tcb_version.f.snp, tcb_version.f.microcode);
}

absl::StatusOr<std::string> DownloadCertificate(const std::string& url) {
  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    return absl::UnknownError("null curl_api is not allowed");
  }
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ResponseHandler);
  std::string certificate;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &certificate);
  if (CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
    curl_easy_cleanup(curl);
    return absl::UnknownError(
        absl::StrCat("Error downloading certificate from '", url, "'"));
  }
  curl_easy_cleanup(curl);
  return certificate;
}

absl::StatusOr<std::string> DownloadCertificate() {
  KernelApi api;
  HATS_ASSIGN_OR_RETURN(std::string url, GetCertificateUrl(api));
  return DownloadCertificate(url);
}
}  // namespace privacy_sandbox::client
