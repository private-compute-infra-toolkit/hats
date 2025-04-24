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

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "opentelemetry/exporters/memory/in_memory_metric_data.h"
#include "opentelemetry/exporters/memory/in_memory_metric_exporter_factory.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/data/point_data.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_factory.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"

namespace privacy_sandbox::tvs {
namespace {

using ::opentelemetry::sdk::metrics::InstrumentDescriptor;
using ::testing::Eq;
using ::testing::Field;
using ::testing::StrEq;

TEST(OtelCounterTest, CounterIncrement) {
  // Initialize an MetricProvider with an InMemoryMetricExporterFactory
  std::shared_ptr<opentelemetry::sdk::metrics::MeterProvider> meter_provider =
      std::make_shared<opentelemetry::sdk::metrics::MeterProvider>();
  std::shared_ptr<
      opentelemetry::exporter::memory::CircularBufferInMemoryMetricData>
      data_storage = std::make_shared<
          opentelemetry::exporter::memory::CircularBufferInMemoryMetricData>(
          10);
  std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> exporter =
      opentelemetry::exporter::memory::InMemoryMetricExporterFactory::Create(
          data_storage);
  std::unique_ptr<opentelemetry::sdk::metrics::MetricReader> reader =
      opentelemetry::sdk::metrics::PeriodicExportingMetricReaderFactory::Create(
          std::move(exporter),
          opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions());
  meter_provider->AddMetricReader(std::move(reader));
  opentelemetry::metrics::Provider::SetMeterProvider(meter_provider);

  OtelCounter app_counter("counter_name", "counter_desc", "counter_unit");
  app_counter.Increment({{"status", "success"}});
  app_counter.IncrementBy(4, {{"status", "success"}});

  meter_provider->ForceFlush();

  std::vector<std::unique_ptr<opentelemetry::sdk::metrics::ResourceMetrics>>
      collected_metrics = data_storage->Get();

  ASSERT_THAT(collected_metrics.size(), Eq(2));
  const opentelemetry::sdk::metrics::MetricData& md =
      collected_metrics[1]->scope_metric_data_[0].metric_data_[0];
  EXPECT_THAT(
      md.instrument_descriptor,
      AllOf(Field(&InstrumentDescriptor::name_, StrEq("counter_name")),
            Field(&InstrumentDescriptor::description_, StrEq("counter_desc")),
            Field(&InstrumentDescriptor::unit_, StrEq("counter_unit"))));
  const opentelemetry::sdk::metrics::PointDataAttributes& dp =
      md.point_data_attr_[0];
  EXPECT_THAT(
      opentelemetry::nostd::get<int64_t>(
          opentelemetry::nostd::get<opentelemetry::sdk::metrics::SumPointData>(
              dp.point_data)
              .value_),
      Eq(5));
  for (auto it = dp.attributes.begin(); it != dp.attributes.end(); ++it) {
    EXPECT_THAT(it->first, StrEq("status"));
    EXPECT_THAT(opentelemetry::nostd::get<std::string>(it->second),
                StrEq("success"));
  }
}

}  // namespace
}  // namespace privacy_sandbox::tvs
