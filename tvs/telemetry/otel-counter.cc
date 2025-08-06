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

#include "tvs/telemetry/otel-counter.h"

#include <map>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "opentelemetry/common/key_value_iterable_view.h"
#include "opentelemetry/metrics/meter.h"
#include "opentelemetry/metrics/provider.h"

namespace pcit::tvs {
namespace {

constexpr absl::string_view kMeterName = "pcit.tvs.TeeVerificationService";
constexpr absl::string_view kMeterVersion = "0.1.0";
}  // namespace

OtelCounter::OtelCounter(absl::string_view name, absl::string_view description,
                         absl::string_view unit) {
  std::shared_ptr<opentelemetry::metrics::MeterProvider> provider =
      opentelemetry::metrics::Provider::GetMeterProvider();
  std::shared_ptr<opentelemetry::metrics::Meter> meter =
      provider->GetMeter(kMeterName, kMeterVersion);
  counter_ = meter->CreateUInt64Counter(name, description, unit);
}

void OtelCounter::IncrementBy(
    int value, const std::map<std::string, std::string>& labels) {
  counter_->Add(value, opentelemetry::common::KeyValueIterableView<
                           std::map<std::string, std::string>>{labels});
}

void OtelCounter::Increment(const std::map<std::string, std::string>& labels) {
  IncrementBy(1, labels);
}

}  // namespace pcit::tvs
