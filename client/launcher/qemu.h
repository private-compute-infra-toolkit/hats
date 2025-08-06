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

#include <memory>
#include <string>
#include <vector>

#include "absl/flags/declare.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "client/launcher/vmm.h"

#ifndef HATS_CLIENT_LAUNCHER_QEMU_H_
#define HATS_CLIENT_LAUNCHER_QEMU_H_

ABSL_DECLARE_FLAG(bool, qemu_use_microvm);

namespace pcit::client {

// Main Qemu Class
class Qemu final : public Vmm {
 public:
  static absl::StatusOr<std::unique_ptr<Qemu>> Create(const Options& options);
  Qemu() = delete;
  Qemu(const Qemu&) = delete;
  Qemu& operator=(const Qemu&) = delete;

  // This function should be called once and only once.
  // The function returns an error if it was called multiple times.
  absl::Status Start() override ABSL_LOCKS_EXCLUDED(mu_);

  // Exposed for unit test.
  std::string GetCommand() const override;

  // Return the file where QEMU stderr and stdout are written.
  absl::StatusOr<std::string> LogFilename() const override
      ABSL_LOCKS_EXCLUDED(mu_);

  // Check status of the QEMU process
  bool CheckStatus() const override;

  // Wait until QEMU terminates.
  void Wait() override ABSL_LOCKS_EXCLUDED(mu_);

  // Shutdown QEMU subprocess.
  void Shutdown() override ABSL_LOCKS_EXCLUDED(mu_);

 private:
  Qemu(std::string binary, std::vector<std::string> args, bool log_to_std);

  const std::string binary_;
  std::vector<std::string> args_;

  mutable absl::Mutex mu_;
  // Whether Qemu was started or not.
  bool started_ ABSL_GUARDED_BY(mu_) = false;
  // Process id of the Qemu process.
  pid_t process_id_ ABSL_GUARDED_BY(mu_);
  // file name where qemu output is written to.
  std::string log_filename_ ABSL_GUARDED_BY(mu_);
  // Whether to log to stdout/stderr.
  const bool log_to_std_ = false;
};

}  // namespace pcit::client

#endif  // HATS_CLIENT_LAUNCHER_QEMU_H_
