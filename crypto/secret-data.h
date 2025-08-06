/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HATS_SECRET_DATA_H_
#define HATS_SECRET_DATA_H_

#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace pcit::crypto {

// Object to store sensitive data. The object helps minimizing data leakage, and
// ensure proper erasure that are often caused by optimization.
// to other functions. The usage of this object reduce the need to explicitly
// case/convert between data types as it can be constructed from strings and
// string_view's, it also return a pointer to the inner array to allow manual
// manipulation and to be passed to functions accepting arrays. Also, it returns
// a string_view to be passed to other functions accepting strings. This is a
// replacement to strings and vectors as the the underlying data might be copied
//  to other location. It is not trivial to ensure proper erasure as
// implementation varies across platform.

class SecretData final {
 public:
  SecretData() = delete;
  explicit SecretData(size_t size);
  explicit SecretData(absl::string_view data);
  SecretData(const SecretData& other);
  SecretData(SecretData&& other);
  SecretData& operator=(const SecretData& other);
  SecretData& operator=(SecretData&& other);
  ~SecretData();

  uint8_t* GetData();
  const uint8_t* GetData() const;
  size_t GetSize() const;
  // The function support size reduction only right now.
  absl::Status Resize(size_t new_size);
  absl::string_view GetStringView() const;
  // Clean the buffer.
  void Cleanse();

 private:
  size_t size_ = 0;
  // Actual size captures the size during the creation of the object.
  // The client might use `Resize()` to shrink the size and we still want to
  // know the actual size to cleanse the whole buffer.
  size_t actual_size_ = 0;
  std::unique_ptr<uint8_t[]> data_;
};

}  // namespace pcit::crypto

#endif  // HATS_SECRET_DATA_H_
