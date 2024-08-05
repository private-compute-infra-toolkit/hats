#ifndef HATS_CRYPTO_AEAD_CRYPTER_H_
#define HATS_CRYPTO_AEAD_CRYPTER_H_

#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"

namespace privacy_sandbox::crypto {

// Predefined associated data for secrets used by the TVS.
constexpr absl::string_view kTvsPrivateKeyAd = "hats_tvs_private_key";
constexpr absl::string_view kSecretAd = "hats_secret";

// Generate a random AES 256 key.
SecretData RandomAeadKey();

// Encrypt a message using AES-256 in GCM mode.
absl::StatusOr<std::string> Encrypt(const SecretData& key,
                                    const SecretData& plaintext,
                                    absl::string_view associated_data);

// Decrypt a message using AES-256 in GCM mode.
absl::StatusOr<SecretData> Decrypt(const SecretData& key,
                                   const SecretData& ciphertext,
                                   absl::string_view associated_data);

}  // namespace privacy_sandbox::crypto

#endif  // HATS_CRYPTO_AEAD_CRYPTER_H_
