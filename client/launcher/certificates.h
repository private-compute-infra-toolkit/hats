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

#ifndef HATS_CLIENT_LAUNCHER_CERTIFICATES_H_
#define HATS_CLIENT_LAUNCHER_CERTIFICATES_H_

#include <string>

#include "absl/status/statusor.h"
#include "client/launcher/kernel-api.h"

namespace pcit::client {

// Get a URL for the current CPU certificate. The method constructs the URL by
// getting the CPU ID, and TcbVersions along the CPU module name.
absl::StatusOr<std::string> GetCertificateUrl(const KernelApiInterface& api);

// Given a `url` download the tee certificate from a given URL.
absl::StatusOr<std::string> DownloadCertificate(const std::string& url);

// Download the certificate for the CPU the process is running on from the
// vendor's key distribution portal.
absl::StatusOr<std::string> DownloadCertificate();

// Try to read tee certificate from a known file location, if no file exists
// download the certificate from the vendor's key distribution portal.
// The method uses advisory locking on the agreed certificate file for
// synchronization across launchers in the machine. The first launcher that
// grabs the lock when the is empty, downloads the certificate while the rest
// wait for it. This way, we download the certificate only once.
absl::StatusOr<std::string> ReadOrDownloadCertificate();

}  // namespace pcit::client
#endif  // HATS_CLIENT_LAUNCHER_CERTIFICATES_
