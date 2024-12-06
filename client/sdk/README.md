# Software Development Kit (SDK)

This directory provides class that clients can use to run software in HATS CVMs.

HATs orchestrator exports a number of RPCs to workload running in a CVM over
Unix Domain Socket `unix:/oak_utils/orchestrator_ipc`.

The orchestrator export an RPC to get secrets obtain from the tee verification
service - `GetKeys()`. The orchestrator also exports Oak's orchestrator RPCs.
One RPC that is worthy of mentioning is `NotifyAppReady()`. The workload can
call the RPC to notify the launcher that its ready to serve requests.

The folder contains the following C++ libraries:

1. hats_orchestrator_client: a wrapper around RPCs exported by the orchestrator.
   Clients should use the library instead of calling the RPCs directly.

1. hats_lightweight_client: a wrapper around RPCs exported by HATs orchestrator.
   This should be used by clients who do not wish to depend on Oak's repository.
