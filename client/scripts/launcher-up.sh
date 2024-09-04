#!/bin/bash
sudo ./launcher_main \
        --tvs_address=localhost:7774 \
        --use_tls=false \
        --launcher_config_path=launcher_config.prototext \
        --tvs_authentication_key=$(cat launcher_hold_user_authentication_private_key_hex) \
        --minloglevel=0 \
        --stderrthreshold=0
