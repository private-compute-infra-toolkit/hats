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

// Helper macros and methods to return and propagate errors with `absl::Status`.

// copybara:strip_begin(internal details, go/totw/121 is sadly non-public)
// This is a branch of //util/task/status_macros.h
//
// See go/totw/121 for guidance on the use of these macros.
// copybara:strip_end

#ifndef HATS_STATUS_MACRO_STATUS_MACROS_H_
#define HATS_STATUS_MACRO_STATUS_MACROS_H_

#include <utility>

#include "gcp_common/gcp-status.h"  // IWYU pragma: keep for type conversion
#include "status_macro/status_builder.h"
#include "status_macro/status_util.h"  // IWYU pragma: keep

// Evaluates an expression that produces a `absl::Status`. If the
// status is not ok, returns it from the current function.
// This also supports expressions that return grpc::Status or
// google::cloud::Status
//
// For example:
//   absl::Status MultiStepFunction() {
//     HATS_RETURN_IF_ERROR(Function(args...));
//     HATS_RETURN_IF_ERROR(foo.Method(args...));
//     return absl::OkStatus();
//   }
//
// The macro ends with a `::privacy_sandbox::status_macro
// ::StatusBuilder` which allows the returned status to be extended with more
// details.  Any chained expressions after the macro will not be evaluated
// unless there is an error.
//
// For example:
//   absl::Status MultiStepFunction() {
//     HATS_RETURN_IF_ERROR(Function(args...)) << "in MultiStepFunction";
//     HATS_RETURN_IF_ERROR(foo.Method(args...)).Log(base_logging::ERROR)
//         << "while processing query: " << query.DebugString();
//     return absl::OkStatus();
//   }
//
// `::privacy_sandbox::status_macro ::StatusBuilder` supports
// adapting the builder chain using a `With` method and a functor.  This allows
// for powerful extensions to the macro.
//
// For example, teams can define local policies to use across their code:
//
//   StatusBuilder TeamPolicy(StatusBuilder builder) {
//     return std::move(builder.Log(base_logging::WARNING).Attach(...));
//   }
//
//   HATS_RETURN_IF_ERROR(foo()).With(TeamPolicy);
//   HATS_RETURN_IF_ERROR(bar()).With(TeamPolicy);
//
// Changing the return type allows the macro to be used with Task and Rpc
// interfaces.  See `::privacy_sandbox::status_macro ::TaskReturn`
// and `rpc::RpcSetStatus` for details.
//
//   void Read(StringPiece name, ::privacy_sandbox::status_macro
//   ::Task* task) {
//     int64 id;
//     HATS_RETURN_IF_ERROR(GetIdForName(name, &id)).With(TaskReturn(task));
//     HATS_RETURN_IF_ERROR(ReadForId(id)).With(TaskReturn(task));
//     task->Return();
//   }
//
// If using this macro inside a lambda, you need to annotate the return type
// to avoid confusion between a `::privacy_sandbox::status_macro
// ::StatusBuilder` and a `absl::Status` type. E.g.
//
//   []() -> absl::Status {
//     HATS_RETURN_IF_ERROR(Function(args...));
//     HATS_RETURN_IF_ERROR(foo.Method(args...));
//     return absl::OkStatus();
//   }
#define HATS_RETURN_IF_ERROR(expr)                                             \
  HATS_STATUS_MACROS_IMPL_ELSE_BLOCKER_                                        \
  if (::privacy_sandbox::status_macro ::status_macro_internal::                \
          StatusAdaptorForMacros status_macro_internal_adaptor = {(expr),      \
                                                                  HATS_LOC}) { \
  } else /* NOLINT */                                                          \
    return status_macro_internal_adaptor.Consume()
// Executes an expression `rexpr` that returns a
// `absl::StatusOr<T>`. On OK, extracts its value into the variable defined by
// `lhs`, otherwise returns from the current function. By default the error
// status is returned unchanged, but it may be modified by an
// `error_expression`. If there is an error, `lhs` is not evaluated; thus any
// side effects that `lhs` may have only occur in the success case.
//
// NOTE: Unlike HATS_RETURN_IF_ERROR, this can only handle absl::StatusOr.
// This will not work on google::cloud::StatusOr
//
// Interface:
//
//   HATS_ASSIGN_OR_RETURN(lhs, rexpr)
//   HATS_ASSIGN_OR_RETURN(lhs, rexpr, error_expression);
//
// WARNING: expands into multiple statements; it cannot be used in a single
// statement (e.g. as the body of an if statement without {})!
//
// Example: Declaring and initializing a new variable (ValueType can be anything
//          that can be initialized with assignment, including references):
//   HATS_ASSIGN_OR_RETURN(ValueType value, MaybeGetValue(arg));
//
// Example: Assigning to an existing variable:
//   ValueType value;
//   HATS_ASSIGN_OR_RETURN(value, MaybeGetValue(arg));
//
// Example: Assigning to an expression with side effects:
//   MyProto data;
//   HATS_ASSIGN_OR_RETURN(*data.mutable_str(), MaybeGetValue(arg));
//   // No field "str" is added on error.
//
// Example: Assigning to a std::unique_ptr.
//   HATS_ASSIGN_OR_RETURN(std::unique_ptr<T> ptr, MaybeGetPtr(arg));
//
// If passed, the `error_expression` is evaluated to produce the return
// value. The expression may reference any variable visible in scope, as
// well as a `::privacy_sandbox::status_macro ::StatusBuilder` object
// populated with the error and named by a single underscore `_`. The expression
// typically uses the builder to modify the status and is returned directly in
// manner similar to HATS_RETURN_IF_ERROR. The expression may, however, evaluate
// to any type returnable by the function, including (void). For example:
//
// Example: Adjusting the error message.
//   HATS_ASSIGN_OR_RETURN(ValueType value, MaybeGetValue(query),
//                    _ << "while processing query " << query.DebugString());
//
// Example: Logging the error on failure.
//   HATS_ASSIGN_OR_RETURN(ValueType value, MaybeGetValue(query), _.LogError());
//
#define HATS_ASSIGN_OR_RETURN(...)                                    \
  HATS_STATUS_MACROS_IMPL_GET_VARIADIC_(                              \
      (__VA_ARGS__, HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_3_, \
       HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_2_))             \
  (__VA_ARGS__)

// =================================================================
// == Implementation details, do not rely on anything below here. ==
// =================================================================
namespace privacy_sandbox::status_macro::internal {
constexpr bool HasPotentialConditionalOperator(const char* lhs, int index) {
  return (index == -1
              ? false
              : (lhs[index] == '?'
                     ? true
                     : ::privacy_sandbox::status_macro ::internal::
                           HasPotentialConditionalOperator(lhs, index - 1)));
}
}  // namespace privacy_sandbox::status_macro::internal

#define HATS_STATUS_MACROS_IMPL_GET_VARIADIC_HELPER_(_1, _2, _3, NAME, ...) NAME
#define HATS_STATUS_MACROS_IMPL_GET_VARIADIC_(args) \
  HATS_STATUS_MACROS_IMPL_GET_VARIADIC_HELPER_ args
#define HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_2_(lhs, rexpr)           \
  HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_(                              \
      HATS_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, rexpr, \
      return std::move(                                                        \
                 HATS_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__))  \
          .status())
#define HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_3_(lhs, rexpr,           \
                                                         error_expression)     \
  HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_(                              \
      HATS_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, rexpr, \
      ::privacy_sandbox::status_macro ::StatusBuilder _(                       \
          std::move(                                                           \
              HATS_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__))     \
              .status(),                                                       \
          HATS_LOC);                                                           \
      (void)_; /* error_expression is allowed to not use this variable */      \
      return (error_expression))
#define HATS_STATUS_MACROS_IMPL_HATS_ASSIGN_OR_RETURN_(statusor, lhs, rexpr, \
                                                       error_expression)     \
  auto statusor = (rexpr);                                                   \
  if (ABSL_PREDICT_FALSE(!statusor.ok())) {                                  \
    error_expression;                                                        \
  }                                                                          \
  {                                                                          \
    static_assert(                                                           \
        #lhs[0] != '(' || #lhs[sizeof(#lhs) - 2] != ')' ||                   \
            !privacy_sandbox::status_macro ::internal::                      \
                HasPotentialConditionalOperator(#lhs, sizeof(#lhs) - 2),     \
        "Identified potential conditional operator, consider not "           \
        "using HATS_ASSIGN_OR_RETURN");                                      \
  }                                                                          \
  HATS_STATUS_MACROS_IMPL_UNPARENTHESIZE_IF_PARENTHESIZED(lhs) =             \
      std::move(statusor).value()
// Internal helpers to check an empty argument.
// The definitions of these macros are borrowed from
// https://t6847kimo.github.io/blog/2019/02/04/Remove-comma-in-variadic-macro.html,
// instead of the google internal approaches which relies on a GNU extension
// support for ##__VA_ARGS__ and is not a part of c++ standards.
#define HATS_STATUS_MACROS_IMPL_TRIGGER_PARENTHESIS(...) ,
#define HATS_STATUS_MACROS_IMPL_ARG3(_0, _1, _2, ...) _2
#define HATS_STATUS_MACROS_IMPL_HAS_COMMA(...) \
  HATS_STATUS_MACROS_IMPL_ARG3(__VA_ARGS__, 1, 0)
#define HATS_STATUS_MACROS_IMPL_IS_EMPTY(...)                       \
  HATS_STATUS_MACROS_IMPL_IS_EMPTY_HELPER(                          \
      HATS_STATUS_MACROS_IMPL_HAS_COMMA(__VA_ARGS__),               \
      HATS_STATUS_MACROS_IMPL_HAS_COMMA(                            \
          HATS_STATUS_MACROS_IMPL_TRIGGER_PARENTHESIS __VA_ARGS__), \
      HATS_STATUS_MACROS_IMPL_HAS_COMMA(__VA_ARGS__(/*empty*/)),    \
      HATS_STATUS_MACROS_IMPL_HAS_COMMA(                            \
          HATS_STATUS_MACROS_IMPL_TRIGGER_PARENTHESIS __VA_ARGS__(/*empty*/)))
#define HATS_STATUS_MACROS_IMPL_PASTES(_0, _1, _2, _3, _4) _0##_1##_2##_3##_4
#define HATS_STATUS_MACROS_IMPL_IS_EMPTY_CASE_0001 ,
#define HATS_STATUS_MACROS_IMPL_IS_EMPTY_HELPER(_0, _1, _2, _3)     \
  HATS_STATUS_MACROS_IMPL_HAS_COMMA(HATS_STATUS_MACROS_IMPL_PASTES( \
      HATS_STATUS_MACROS_IMPL_IS_EMPTY_CASE_, _0, _1, _2, _3))
// Internal helpers for macro expansion.
#define HATS_STATUS_MACROS_IMPL_EAT(...)
#define HATS_STATUS_MACROS_IMPL_REM(...) __VA_ARGS__
#define HATS_STATUS_MACROS_IMPL_EMPTY()
// Internal helpers for if statement.
#define HATS_STATUS_MACROS_IMPL_IF_1(_Then, _Else) _Then
#define HATS_STATUS_MACROS_IMPL_IF_0(_Then, _Else) _Else
#define HATS_STATUS_MACROS_IMPL_IF(_Cond, _Then, _Else)               \
  HATS_STATUS_MACROS_IMPL_CONCAT_(HATS_STATUS_MACROS_IMPL_IF_, _Cond) \
  (_Then, _Else)
// Expands to 1 if the input is parenthesized. Otherwise expands to 0.
#define HATS_STATUS_MACROS_IMPL_IS_PARENTHESIZED(...) \
  HATS_STATUS_MACROS_IMPL_IS_EMPTY(HATS_STATUS_MACROS_IMPL_EAT __VA_ARGS__)
// If the input is parenthesized, removes the parentheses. Otherwise expands to
// the input unchanged.
#define HATS_STATUS_MACROS_IMPL_UNPARENTHESIZE_IF_PARENTHESIZED(...) \
  HATS_STATUS_MACROS_IMPL_IF(                                        \
      HATS_STATUS_MACROS_IMPL_IS_PARENTHESIZED(__VA_ARGS__),         \
      HATS_STATUS_MACROS_IMPL_REM, HATS_STATUS_MACROS_IMPL_EMPTY())  \
  __VA_ARGS__
// Internal helper for concatenating macro values.
#define HATS_STATUS_MACROS_IMPL_CONCAT_INNER_(x, y) x##y
#define HATS_STATUS_MACROS_IMPL_CONCAT_(x, y) \
  HATS_STATUS_MACROS_IMPL_CONCAT_INNER_(x, y)
// The GNU compiler emits a warning for code like:
//
//   if (foo)
//     if (bar) { } else baz;
//
// because it thinks you might want the else to bind to the first if.  This
// leads to problems with code like:
//
//   if (do_expr) HATS_RETURN_IF_ERROR(expr) << "Some message";
//
// The "switch (0) case 0:" idiom is used to suppress this.
#define HATS_STATUS_MACROS_IMPL_ELSE_BLOCKER_ \
  switch (0)                                  \
  case 0:                                     \
  default:  // NOLINT

// Forward decl to avoid a heavy dependency on grpc.
namespace grpc {
class Status;
}
// v2_29 is inline namespace
namespace google::cloud {
class Status;
}

namespace privacy_sandbox::status_macro {
namespace status_macro_internal {
// Provides a conversion to bool so that it can be used inside an if statement
// that declares a variable.
class StatusAdaptorForMacros {
 public:
  StatusAdaptorForMacros(const absl::Status& status, SourceLocation loc)
      : builder_(status, loc) {}

  StatusAdaptorForMacros(const grpc::Status& grpc_status, SourceLocation loc)
      : builder_(ToAbslStatus(grpc_status), loc) {}

  StatusAdaptorForMacros(const google::cloud::v2_29::Status& cloud_status,
                         SourceLocation loc)
      : builder_(::privacy_sandbox::gcp_common::GcpToAbslStatus(cloud_status),
                 loc) {}

  StatusAdaptorForMacros(absl::Status&& status, SourceLocation loc)
      : builder_(std::move(status), loc) {}

  StatusAdaptorForMacros(const StatusBuilder& builder, SourceLocation loc)
      : builder_(builder) {}

  StatusAdaptorForMacros(StatusBuilder&& builder, SourceLocation loc)
      : builder_(std::move(builder)) {}

  StatusAdaptorForMacros(const StatusAdaptorForMacros&) = delete;
  StatusAdaptorForMacros& operator=(const StatusAdaptorForMacros&) = delete;

  explicit operator bool() const { return ABSL_PREDICT_TRUE(builder_.ok()); }

  StatusBuilder&& Consume() { return std::move(builder_); }

 private:
  StatusBuilder builder_;
};
}  // namespace status_macro_internal
}  // namespace privacy_sandbox::status_macro

#endif  // HATS_STATUS_MACRO_STATUS_MACROS_H_
