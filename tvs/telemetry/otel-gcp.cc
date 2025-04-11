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

#include <memory>
#include <string>
#include <utility>

#include <grpcpp/ext/otel_plugin.h>
#include <grpcpp/grpcpp.h>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "gcp_common/flags.h"
#include "google/cloud/monitoring/v3/metric_connection.h"
#include "google/cloud/opentelemetry/monitoring_exporter.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_factory.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/meter_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/view_factory.h"
#include "tvs/telemetry/otel.h"

namespace privacy_sandbox::tvs {

namespace {

void AddLatencyView(const std::string& name, const std::string& unit,
                    opentelemetry::sdk::metrics::MeterProvider& provider) {
  auto histogram_config = std::make_shared<
      opentelemetry::sdk::metrics::HistogramAggregationConfig>();
  // Histogram boundary buckets for GRPC latency as recommended by
  // https://github.com/grpc/proposal/blob/master/A66-otel-stats.md.
  histogram_config->boundaries_ = {
      0,     0.00001, 0.00005, 0.0001, 0.0003, 0.0006, 0.0008, 0.001, 0.002,
      0.003, 0.004,   0.005,   0.006,  0.008,  0.01,   0.013,  0.016, 0.02,
      0.025, 0.03,    0.04,    0.05,   0.065,  0.08,   0.1,    0.13,  0.16,
      0.2,   0.25,    0.3,     0.4,    0.5,    0.65,   0.8,    1,     2,
      5,     10,      20,      50,     100};
  provider.AddView(
      opentelemetry::sdk::metrics::InstrumentSelectorFactory::Create(
          opentelemetry::sdk::metrics::InstrumentType::kHistogram, name, unit),
      opentelemetry::sdk::metrics::MeterSelectorFactory::Create(
          "grpc-c++", grpc::Version(), ""),
      opentelemetry::sdk::metrics::ViewFactory::Create(
          name, "", unit,
          opentelemetry::sdk::metrics::AggregationType::kHistogram,
          std::move(histogram_config)));
}

}  // namespace

absl::Status InitializeTelemetry() {
  auto meter_provider =
      std::make_shared<opentelemetry::sdk::metrics::MeterProvider>();

  auto connection = google::cloud::monitoring_v3::MakeMetricServiceConnection();
  auto exporter = google::cloud::otel::MakeMonitoringExporter(
      google::cloud::Project(absl::GetFlag(FLAGS_project_id)),
      std::move(connection));
  auto reader =
      opentelemetry::sdk::metrics::PeriodicExportingMetricReaderFactory::Create(
          std::move(exporter),
          opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions());
  // The default histogram boundaries are not granular enough for RPCs. Override
  // the "grpc.server.call.duration" view as recommended by
  // https://github.com/grpc/proposal/blob/master/A66-otel-stats.md.
  AddLatencyView("grpc.server.call.duration", "s", *meter_provider);
  AddLatencyView("grpc.client.attempt.duration", "s", *meter_provider);
  meter_provider->AddMetricReader(std::move(reader));
  return grpc::OpenTelemetryPluginBuilder()
      .SetMeterProvider(std::move(meter_provider))
      .BuildAndRegisterGlobal();
}
}  // namespace privacy_sandbox::tvs
