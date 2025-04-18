// Copyright 2025 Google LLC.
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

#ifndef HATS_TVS_TELEMETRY_OTEL_COUNTER_
#define HATS_TVS_TELEMETRY_OTEL_COUNTER_

#include <map>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "opentelemetry/metrics/provider.h"

namespace privacy_sandbox::tvs {

class OtelCounter final {
 public:
  explicit OtelCounter(absl::string_view name, absl::string_view description,
                       absl::string_view unit);

  void Increment(const std::map<std::string, std::string>& labels);
  void IncrementBy(int value, const std::map<std::string, std::string>& labels);

 private:
  std::unique_ptr<opentelemetry::metrics::Counter<uint64_t>> counter_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_TELEMETRY_OTEL_COUNTER_
