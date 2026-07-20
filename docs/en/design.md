# Design Rationale

Detailed explanation of the four core mechanisms. The README's "Core Features" section is a condensed version of this document.

## Verifier Decoupled from TEE Platforms

In traditional remote attestation, the verifier must embed dedicated evidence parsers and signature verification code for each TEE platform — adding a new TEE type requires adding parsing logic and certificate chain verification to the verifier. This means TEE platform upgrades (certificate format changes, signature algorithm replacements) necessarily force verifier updates, effectively coupling the verifier to the platform.

This solution extracts "how to verify a given TEE's evidence" from the verifier and encapsulates it into independent wasm components. When an attester initiates attestation, it submits both the evidence and the corresponding wasm verification component to the verifier. The verifier only does three things:

1. Check whether the wasm component's sha256 is in the configured whitelist (confirming the component's provenance is trusted)
2. Invoke the component's evaluate interface in the wasmtime sandbox, passing the evidence and challenge nonce
3. Compare the claims returned by the component against local policy (e.g., trusted root list)

The verifier does not need to understand the internal format of evidence, does not need to know what signature algorithm was used, and does not even need to know about zero-knowledge proofs — all of this is handled inside the wasm component. TEE platform upgrades only require updating the wasm component and recomputing the sha256 whitelist; the verifier code needs no changes.

> **Exception**: CCA/CSV verification depends on ccatoken/csv-rs (OpenSSL), iTrustee verification depends on libteeverifier.so FFI, and VirtCCA verification depends on OpenSSL + COSE/CBOR. These libraries cannot be compiled to wasm32-wasip1. Therefore, full verification for these four TEE types is placed in the verifier host, with wasm appraisers only performing field passthrough and nonce comparison. TDX still follows the "all in wasm" approach (dcap-qvl supports wasm32).

## Challenge-Proof Cryptographic Binding

One of the core security goals of remote attestation is to prevent replay attacks: an attacker intercepts a valid piece of evidence and resubmits it repeatedly. Without protection mechanisms, the verifier would issue EARs multiple times.

Common anti-replay approaches embed timestamps or incrementing counters in tokens, but these have window problems — timestamps can still be replayed before expiry, and counters require both parties to synchronize state. This solution takes a different path: making the challenge nonce directly participate in the zero-knowledge proof's constraint system, cryptographically coupling the proof with the current nonce. The specific process:

1. The verifier issues a 32-byte random nonce to the attester
2. The attester encodes the nonce as a scalar field element via `nonce_to_scalar = Fr::from_le_bytes_mod_order(blake2s_256(nonce))` and places it in the Groth16 circuit as the last public input, then generates a proof. The resulting proof assumes the nonce is a specific value
3. During verification, the wasm component reads the public_inputs corresponding to the proof, extracts the last field (the nonce scalar claimed by the attester), computes the scalar from the verifier's expected_report_data (the raw nonce bytes of the current challenge) using the same algorithm, and strictly compares the two
4. Only when Groth16 verification passes **and** nonce comparison passes does the component return verification: passed

If an attacker intercepts historical evidence and replays it: the nonce field in the proof corresponds to the old challenge, while the verifier's expected_report_data is the new challenge's nonce — the comparison in step 3 will necessarily fail. This is not a time-based judgment but a cryptographic inequality with no bypass path.

## Zero-Knowledge Device Identity Proofs

The attester uses a Shrubs accumulator to compress a set of device public keys into a root list, then uses a Merkle path to prove it is in the whitelist. The entire process does not expose the attestation key or the specific index. The verifier only knows the evidence came from some trusted device and cannot identify the specific device.

Circuit details: [hydra.md](hydra.md).

## Three Independent Trust Anchors

Component whitelist (sha256) blocks arbitrary wasm uploads, nonce binding blocks evidence replay, and the trusted root list blocks unauthorized devices. The three mechanisms are independent of each other — an attacker must simultaneously break all three to obtain a signed EAR.

## EAR Self-Containment

EAR is an ES256-signed JWT. Once issued, it can be independently verified by any third party holding the public key. The verifier is just the issuer — no verifier online dependency, no additional network round-trips needed. The relying-party can complete signature verification and decoding locally with the public key.
