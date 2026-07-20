//! gRPC protocol contract. tonic-build generates code at compile time.
//!
//! Shared across three parties: attester uses server to implement AttesterService,
//! verifier uses server to implement VerifierService, and the relying-party acts
//! as a client to both.

tonic::include_proto!("unified_attestation");
