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

#include "crypto/secret-data.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/mem.h"

namespace pcit::crypto {

SecretData::SecretData(size_t size)
    : size_(size), actual_size_(size), data_(new uint8_t[size_]) {}

SecretData::SecretData(absl::string_view data)
    : size_(data.size()), actual_size_(size_) {
  data_ = std::unique_ptr<uint8_t[]>(new uint8_t[size_]);
  memcpy(GetData(), data.data(), size_);
}

SecretData::SecretData(const SecretData& other) { *this = other; }

SecretData::SecretData(SecretData&& other) { *this = std::move(other); }

SecretData& SecretData::operator=(const SecretData& other) {
  if (this != &other) {
    size_ = other.size_;
    actual_size_ = other.actual_size_;
    data_ = std::unique_ptr<uint8_t[]>(new uint8_t[size_]);
    memcpy(GetData(), other.GetData(), GetSize());
  }
  return *this;
}

SecretData& SecretData::operator=(SecretData&& other) {
  std::swap(data_, other.data_);
  std::swap(size_, other.size_);
  std::swap(actual_size_, other.actual_size_);
  return *this;
}

SecretData::~SecretData() { Cleanse(); }

uint8_t* SecretData::GetData() { return data_.get(); }

const uint8_t* SecretData::GetData() const { return data_.get(); }

size_t SecretData::GetSize() const { return size_; }

absl::Status SecretData::Resize(size_t new_size) {
  if (new_size > size_) {
    return absl::InvalidArgumentError("Size increase is not supported.");
  }
  size_ = new_size;
  return absl::OkStatus();
}

absl::string_view SecretData::GetStringView() const {
  return absl::string_view(reinterpret_cast<const char*>(data_.get()), size_);
}

void SecretData::Cleanse() { OPENSSL_cleanse(data_.get(), actual_size_); }

}  // namespace pcit::crypto
