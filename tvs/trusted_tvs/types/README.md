# Trusted TVS Types

The directory defines traits used by the trusted TVS code.
The client can customize TVS by implementing traits and pass them to TVS.
For instance, KeyProvider is used by TVS to provision the handshake keys and
to fetch client authentication keys and secrets to be returned upon successful
attestation.
