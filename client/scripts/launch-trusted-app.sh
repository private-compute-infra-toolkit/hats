#!/bin/bash

# Launch the trusted program. TVS output is passed as `$1`.
/usr/bin/trusted-app --port=50051 --parc_server_address=10.0.2.100 --parc_server_port=8889 --onperm_private_key=$1
