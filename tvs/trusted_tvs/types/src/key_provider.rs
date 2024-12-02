// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::vec::Vec;

/// Trait to provide key materials to TVS service.
pub trait KeyProvider: Sync + Send {
    /// Primary private key used by TVS for handshake.
    fn get_primary_private_key(&self) -> anyhow::Result<Vec<u8>>;
    /// Secondary private key used by TVS for handshake.
    fn get_secondary_private_key(&self) -> Option<anyhow::Result<Vec<u8>>>;
    /// Get the registered user_id for `user_authentication_public_key`.
    fn user_id_for_authentication_key(
        &self,
        user_authentication_public_key: &[u8],
    ) -> anyhow::Result<i64>;
    /// Secret for `user_id`, to be returned if the user passes attestation verification.
    fn get_secrets_for_user_id(&self, user_id: i64) -> anyhow::Result<Vec<u8>>;
}
