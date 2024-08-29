#!/bin/bash
echo '0000000000000000000000000000000000000000000000000000000000000001' > tvs_hold_noise_kk_private_key_hex
# uncompressed public key generated with P256 from the noise_kk private key.
echo '04a99c16a302716404b075086c8c125ea93d0822330f8a46675c8f7e5760478024811211845d43e6addae5280660ba3b5ba0f78834b79ec9449b626a725728b76d' > orchestrator_hold_noise_kk_public_key_hex
./key-gen --key-type=x25519-hkdf-sha256 > /tmp/hats-test-keygen
cat /tmp/hats-test-keygen | grep Public | awk '{split($0,a," "); print a[2]}' > public_hold_public_hpke_key_hex
cat /tmp/hats-test-keygen | grep Private | awk '{split($0,a," "); print a[2]}' > tvs_hold_private_hpke_key_hex
./key-gen --key-type=secp128r1 > /tmp/hats-test-keygen
cat /tmp/hats-test-keygen | grep Public | awk '{split($0,a," "); print a[2]}' > tvs_hold_user_authentication_public_key_hex
cat /tmp/hats-test-keygen | grep Private | awk '{split($0,a," "); print a[2]}' > launcher_hold_user_authentication_private_key_hex
rm -f /tmp/hats-test-keygen
