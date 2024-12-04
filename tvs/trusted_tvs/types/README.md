# Trusted TVS Types

The directory defines traits used by the trusted TVS code.
The client can customize TVS by implementing traits and pass them to TVS.

The crate provides two traits:
1. Keyprovider: used by TVS to provision the handshake keys and
to fetch client authentication keys and secrets to be returned upon successful
attestation.
1. EvidenceValidator: validate attestation evidence against a given measurements
(appraisal policies).
