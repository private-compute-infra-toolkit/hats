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

// Return(foo) and ReturnVoid adaptors, for use with `StatusBuilder::With()`.
//
// These simplify interoperability between `Status` and non-`Status` code when
// using `HATS_RETURN_IF_ERROR` and `HATS_ASSIGN_OR_RETURN`. `Return(foo)`
// converts a `StatusBuilder` into `foo`, which can be any value, while
// `ReturnVoid` converts a `StatusBuilder` into void.

#ifndef HATS_STATUS_MACRO_RETURN_H_
#define HATS_STATUS_MACRO_RETURN_H_

#include <utility>

#include "absl/meta/type_traits.h"
#include "absl/status/status.h"

namespace privacy_sandbox::status_macros {
namespace internal_return {
template <typename T>
struct ReturnImpl;
}  // namespace internal_return

// Adaptor that converts a `StatusBuilder` into the provided value of any type.
//
// Useful for adapting `HATS_RETURN_IF_ERROR` and `HATS_ASSIGN_OR_RETURN` macros
// in code with non-`Status` return types. For example:
//
//   bool UpdateWidget() {
//     HATS_ASSIGN_OR_RETURN(foo_, GetFoo(),
//                           _.LogWarning().With(status_macros::Return(false)));
//     HATS_ASSIGN_OR_RETURN(bar_, GetBar(),
//                           _.LogWarning().With(status_macros::Return(false)));
//     return true;
//   }
//
//   std::unique_ptr<Widget> CreateWidget() {
//     HATS_ASSIGN_OR_RETURN(
//         auto w, Widget::Create(),
//         _.LogWarning().With(status_macros::Return(nullptr)));
//     HATS_RETURN_IF_ERROR(w->Prepare())
//         .LogWarning()
//         .With(status_macros::Return(nullptr));
//     return w;
//   }
//
// Style guide exception for rvalue refs (cl/178698098). This allows move-only
// types to be returned.
template <typename T>
internal_return::ReturnImpl<absl::decay_t<T>> Return(T&& value);

// Adaptor that converts a `StatusBuilder` to void.
//
// Useful for adapting `HATS_RETURN_IF_ERROR` and `HATS_ASSIGN_OR_RETURN` macros
// in methods with void return types. For example:
//
//   void ProcessWidget(const Widget& w) {
//     HATS_RETURN_IF_ERROR(PrepareWidget(w))
//         .LogWarning()
//         .With(status_macros::ReturnVoid());
//     HATS_RETURN_IF_ERROR(PackageWidget(w))
//         .LogWarning()
//         .With(status_macros::ReturnVoid());
//   }
//
struct ReturnVoid {
  void operator()(const absl::Status&) const {}
};

//
// Implementation details follow.
//
namespace internal_return {

template <typename T>
struct ReturnImpl {
  T value;
  T operator()(const absl::Status&) const& { return value; }
  T operator()(const absl::Status&) && { return std::move(value); }
};

}  // namespace internal_return

template <typename T>
inline internal_return::ReturnImpl<absl::decay_t<T>> Return(T&& value) {
  return internal_return::ReturnImpl<absl::decay_t<T>>{std::forward<T>(value)};
}

}  // namespace privacy_sandbox::status_macros

#endif  // HATS_STATUS_MACRO_RETURN_H_
