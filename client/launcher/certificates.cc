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

#include <iostream>
#include <string>

#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "curl/curl.h"
namespace privacy_sandbox::client {
namespace {
size_t ResponseHandler(char* contents, size_t byte_size, size_t num_bytes,
                       std::string* output) {
  output->append(contents, byte_size * num_bytes);
  return byte_size * num_bytes;
}
}  // namespace

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
}  // namespace privacy_sandbox::client
