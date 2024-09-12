#!/bin/bash
echo "Running TVS server on port 7774"

./tvs-server_main \
        --primary_private_key="$(cat tvs_hold_noise_kk_private_key_hex)" \
        --user_key_id=64 \
        --user_public_key="$(cat public_hold_public_hpke_key_hex)" \
        --user_secret="$(cat tvs_hold_private_hpke_key_hex)" \
        --user_authentication_public_key="$(cat tvs_hold_user_authentication_public_key_hex)" \
        --port=7774 \
        --appraisal_policy_file='appraisal_policy.prototext'
