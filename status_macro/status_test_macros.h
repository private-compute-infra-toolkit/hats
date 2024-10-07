// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HATS_STATUS_MACRO_STATUS_TEST_MACROS_H_
#define HATS_STATUS_MACRO_STATUS_TEST_MACROS_H_

#include <utility>  // IWYU pragma: keep for std::move

#include "absl/status/status_matchers.h"
#include "status_macro/status_util.h"  // IWYU pragma: keep for ToAbslStatus

namespace privacy_sandbox {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;

// Check that expression returning absl::Status is ok
#define HATS_EXPECT_OK(expression) EXPECT_THAT(expression, IsOk())
#define HATS_ASSERT_OK(expression) ASSERT_THAT(expression, IsOk())
// Check that expression returning grpc::Status is ok
#define HATS_EXPECT_OK_GRPC(expression) \
  HATS_EXPECT_OK(privacy_sandbox::status_macro::ToAbslStatus(expression))
// Check that StatusOr lhs is Ok and holds value
// Value can be testing pieces, like EqualsProto, strings, allof, etc.
#define HATS_EXPECT_OK_AND_HOLDS(lhs, value) \
  EXPECT_THAT(lhs, IsOkAndHolds(value))
#define HATS_ASSERT_OK_AND_HOLDS(lhs, value) \
  ASSERT_THAT(lhs, IsOkAndHolds(value))

// Expect that Status/StatusOr lhs has non-ok status
#define HATS_EXPECT_STATUS(lhs, status) EXPECT_THAT(lhs, StatusIs(status))
// Expect that grpc::Status/StatusOr lhs has non-ok status that casts to the
// provided absl::Status
#define HATS_EXPECT_STATUS_GRPC(lhs, absl_status)                      \
  HATS_EXPECT_STATUS(privacy_sandbox::status_macro::ToAbslStatus(lhs), \
                     absl_status)
// Expect that Status/StatusOr lhs has type status with message
// message can be a string, or e.g. HasSubstr("text")
#define HATS_EXPECT_STATUS_MESSAGE(lhs, status, message) \
  EXPECT_THAT(lhs, StatusIs(status, message))
// Asserts rexpr (a StatusOr) is ok, then assigns its value to lhs
// lhs can be a declaration (int x), or a previously declared variable
#define HATS_ASSERT_OK_AND_ASSIGN(lhs, rexpr)                                  \
  _IMPL_HATS_ASSERT_OK_AND_ASSIGN(_CONCAT_MACRO(_status_or, __COUNTER__), lhs, \
                                  rexpr)

// Helpers for HATS_ASSERT_OK_and_assign
#define _CONCAT_IMPL(x, y) x##y
#define _CONCAT_MACRO(x, y) _CONCAT_IMPL(x, y)
#define _IMPL_HATS_ASSERT_OK_AND_ASSIGN(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                    \
  HATS_ASSERT_OK(statusor) << statusor.status();              \
  lhs = std::move(statusor.value())

}  // namespace privacy_sandbox

#endif  // HATS_STATUS_MACRO_STATUS_TEST_MACROS_H_
