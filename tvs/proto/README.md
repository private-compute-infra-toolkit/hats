# TVS protos

The directory contains protos used by TVS:

*   appraisal_policies.proto: describe the format of appraisal policies. The
    policies used to validate the measurements in attestation reports.
*   tvs.proto: describes RPCs exported by TVS server to the client.
*   tvs_messages.proto: describes the messages used by the TVS. The proto
    describes the format of both the encrypted and plain text messages. Note
    that TVS encrypt messages in the application layer.
