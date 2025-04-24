// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "cache/expiring_cache.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::cache {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Pointee;
using ::testing::StrEq;

TEST(ExpiringCacheTest, InsertAndLookupString) {
  ExpiringCache<std::string, std::string> cache(absl::Seconds(1));
  auto value_ptr = std::make_unique<std::string>("test_string_1");
  cache.Insert("key1", std::move(value_ptr));

  EXPECT_THAT(cache.Lookup("key1"),
              AllOf(NotNull(), Pointee(StrEq("test_string_1"))));
}

TEST(ExpiringCacheTest, LookupNonExistingKeyString) {
  ExpiringCache<std::string, std::string> cache(absl::Seconds(1));
  EXPECT_THAT(cache.Lookup("non_existent_key"), IsNull());
}

TEST(ExpiringCacheTest, EntryExpiresString) {
  ExpiringCache<std::string, std::string> cache(absl::Milliseconds(100));
  auto value_ptr = std::make_unique<std::string>("expired_value");
  cache.Insert("key2", std::move(value_ptr));

  absl::SleepFor(absl::Milliseconds(200));  // Wait for longer than the TTL

  EXPECT_THAT(cache.Lookup("key2"), IsNull());
}

TEST(ExpiringCacheTest, EntryRemainsBeforeExpiryString) {
  ExpiringCache<std::string, std::string> cache(absl::Seconds(2));
  auto value_ptr = std::make_unique<std::string>("still_here");
  cache.Insert("key3", std::move(value_ptr));

  absl::SleepFor(absl::Seconds(1));  // Wait for shorter than the TTL

  EXPECT_THAT(cache.Lookup("key3"),
              AllOf(NotNull(), Pointee(StrEq("still_here"))));
}

TEST(ExpiringCacheTest, EraseExistingKeyString) {
  ExpiringCache<int, std::string> cache(absl::Seconds(1));
  auto value_ptr = std::make_unique<std::string>("to_be_erased");
  cache.Insert(1, std::move(value_ptr));

  // Verify it exists before erasing
  auto result = cache.Lookup(1);
  EXPECT_THAT(result, AllOf(NotNull(), Pointee(StrEq("to_be_erased"))));

  cache.Erase(1);

  // Verify it's gone after erasing
  EXPECT_THAT(cache.Lookup(1), IsNull());

  // Verify original value still exists
  EXPECT_THAT(result, AllOf(NotNull(), Pointee(StrEq("to_be_erased"))));
}

TEST(ExpiringCacheTest, EraseNonExistingKeyString) {
  ExpiringCache<int, std::string> cache(absl::Seconds(1));

  // Erasing a non-existing key should not cause issues
  cache.Erase(99);

  // Verify it's still not there
  EXPECT_THAT(cache.Lookup(99), IsNull());
}

TEST(ExpiringCacheTest, MultipleInsertsAndLookupsString) {
  ExpiringCache<int, std::string> cache(absl::Seconds(1));
  cache.Insert(10, std::make_unique<std::string>("value_ten"));
  cache.Insert(20, std::make_unique<std::string>("value_twenty"));

  EXPECT_THAT(cache.Lookup(10), AllOf(NotNull(), Pointee(StrEq("value_ten"))));
  EXPECT_THAT(cache.Lookup(20),
              AllOf(NotNull(), Pointee(StrEq("value_twenty"))));
  EXPECT_THAT(cache.Lookup(30), IsNull());  // Non-existent key
}

TEST(ExpiringCacheTest, ReplaceExistingKeyString) {
  ExpiringCache<std::string, std::string> cache(absl::Seconds(1));
  cache.Insert("key4", std::make_unique<std::string>("first_value"));
  cache.Insert("key4", std::make_unique<std::string>(
                           "second_value"));  // Replaces the old value

  EXPECT_THAT(cache.Lookup("key4"),
              AllOf(NotNull(), Pointee(StrEq("second_value"))));
}

TEST(ExpiringCacheTest, SizeDecrementsOnErase) {
  ExpiringCache<int, std::string> cache(absl::Seconds(10));
  ASSERT_THAT(cache.Size(), Eq(0));
  cache.Insert(1, std::make_unique<std::string>("one"));
  cache.Insert(2, std::make_unique<std::string>("two"));
  ASSERT_THAT(cache.Size(), Eq(2));
  cache.Erase(1);
  EXPECT_THAT(cache.Size(), Eq(1));
  cache.Erase(2);
  EXPECT_THAT(cache.Size(), Eq(0));
}

TEST(ExpiringCacheTest, ClearOnPopulatedCache) {
  ExpiringCache<int, std::string> cache(absl::Seconds(10));
  cache.Insert(1, std::make_unique<std::string>("one"));
  cache.Insert(2, std::make_unique<std::string>("two"));
  ASSERT_THAT(cache.Size(), Eq(2));
  cache.Clear();
  EXPECT_THAT(cache.Size(), Eq(0));
  EXPECT_THAT(cache.Lookup(1), IsNull());
  EXPECT_THAT(cache.Lookup(2), IsNull());
}

TEST(ExpiringCacheTest, CleanExpiredRemovesOnlyExpiredItems) {
  ExpiringCache<int, std::string> cache(absl::Milliseconds(200));
  cache.Insert(1,
               std::make_unique<std::string>("item1"));  // Expires at T + 200ms
  ASSERT_THAT(cache.Size(), Eq(1));

  // Wait for 100ms (less than TTL)
  absl::SleepFor(absl::Milliseconds(100));

  cache.Insert(2, std::make_unique<std::string>(
                      "item2"));  // Expires at T + 100ms + 200ms = T + 300ms
  ASSERT_THAT(cache.Size(), Eq(2));

  absl::SleepFor(absl::Milliseconds(150));

  cache.CleanExpired();  // Should remove only item 1

  EXPECT_THAT(cache.Size(), Eq(1));
  EXPECT_THAT(cache.Lookup(1), IsNull());
  EXPECT_THAT(cache.Lookup(2), AllOf(NotNull(), Pointee(StrEq("item2"))));
}

}  // namespace
}  // namespace privacy_sandbox::cache
