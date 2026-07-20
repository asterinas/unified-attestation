# Hygon CSV Path

Hygon CSV remote attestation: hardware root signature + nonce binding. CSV real verification runs on the verifier host (csv-rs uses OpenSSL, cannot cross-compile to wasm32). The wasm appraiser only does field passthrough and nonce comparison, following the same pattern as the [CCA path](cca.md).

## Certificate Chain

```
HRK (Hygon Root Key, self-signed)
 └─ HSK (Hygon Signing Key)
     └─ CEK (Chip Endorsement Key)
         └─ PEK (Platform Endorsement Key)
             └─ TEE attestation report
```

- HRK: embedded in the verifier binary (`verifier/assets/hygon_hrk.cert`), not changeable online
- HSK / CEK: published by chip_id dimension. Can be cached offline at `<cert_dir>/hsk_cek/<chip_id>/hsk_cek.cert` or fetched online via `policy.csv.allow_kds_fetch = true` from `https://cert.hygon.cn/hsk_cek?snumber=<chip_id>`
- PEK: submitted together with the attestation evidence

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant At as attester
    participant AA as attestation-agent<br/>(REST)
    participant TEE as Hygon CSV Hardware
    participant V as verifier host
    participant W as wasm appraiser<br/>(csv)
    participant RP as relying-party

    RP->>At: GetEvidence { tee_type=csv, nonce }
    At->>AA: GET /aa/evidence?runtime_data=base64(nonce)
    AA->>TEE: request attestation report (mnonce/report_data bound to nonce)
    TEE-->>AA: report + cert_chain (PEK required, HSK/CEK optional)
    AA-->>At: CSV evidence (JSON)
    At-->>RP: { evidence, wasm_component }

    RP->>V: Verify { tee_type=csv, nonce, evidence, wasm_component }

    V->>V: verify sha256 whitelist
    V->>V: csv-rs HRK→HSK→CEK→PEK→report chain verification
    V->>V: report.report_data == padded(nonce, 64)
    V->>V: chip_id whitelist (policy.csv.trusted_chip_ids)
    V->>V: extract measurements and inject into evidence JSON (chip_id, measurement, vm_version, policy_nodbg, policy_noks)

    V->>W: evaluate(evidence, expected_report_data=nonce)
    W-->>V: claims { tee_type=csv, nonce_bound=true, evidence_size, chip_id, measurement, policy_nodbg, policy_noks }

    V-->>RP: EAR JWT (ES256)
    RP->>RP: verify EAR signature locally + compare eat_nonce
```

## Evidence Schema

```json
{
  "csv_evidence_b64": "<base64(Hygon CSV evidence JSON, containing attestation_report + cert_chain + serial_number)>",
  "nonce": "<base64url nonce>"
}
```

The inner structure of `csv_evidence` is produced by guest-components AA, with main fields: `attestation_report` (V1/V2, containing mnonce, report_data, measure, etc.), `cert_chain.pek` (required), `cert_chain.hsk_cek` (optional), `serial_number` (chip_id).

## Configuration

verifier-side `[policy.csv]`:

| key | description |
|---|---|
| `enabled` | Whether to enable host-side verification. When false, skip entirely (demo only) |
| `cert_dir` | HSK/CEK offline cache directory, default `/opt/hygon/csv` |
| `allow_kds_fetch` | Whether to fetch from KDS online on cache miss |
| `trusted_chip_ids` | chip_id whitelist (serial_number text). Empty = no whitelist |

attester-side is the same as CCA: `aa_endpoint` points to guest-components `api-server-rest`.

Templates: `config/verifier-csv.toml` + `config/attester-csv.toml`.

## End-to-End Test

Requires Hygon CSV CPU + guest-components AA + HSK/CEK cache or KDS reachable.

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-csv.toml > /tmp/verifier-csv.log 2>&1 &
./target/release/attester --config config/attester-csv.toml > /tmp/attester-csv.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type csv \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-csv.jwt
```

## Limitations

- HRK is embedded; if Hygon rotates the root, the verifier binary must be re-released
- AA currently only covers V1/V2 attestation reports for CSV evidence; V3 requires a synchronized csv-rs upgrade
- End-to-end smoke test requires a real Hygon CSV CPU; locally, only compilation + static whitelist regression is possible

## CSV + hydra Stacking

For `tee_type = csv-hydra`, the wasm evidence flow over gRPC is identical to CSV-only; the only difference is the emitted `tee_type` claim is `csv-hydra`.

Device-identity zero-knowledge proof runs on an independent Hydra TCP channel: verifier / attester / relying-party stay connected; the verifier batches for 120s, updates the shrubs tree, and broadcasts a PublicContext. The attester builds the Groth16 EvidenceReply locally after receiving the encrypted ResponseDeviceInfor and ships it to the RP over a short-lived TCP connection. See [hydra.md](hydra.md) for config, ports, message types, and two-step commands.

Templates: `config/verifier-csv-hydra.toml` + `config/attester-csv-hydra.toml` (both carry `[hydra]`).

### End-to-end test (csv-hydra)

Add two things to the CSV-only steps: give verifier and attester a `[hydra]` section, keep all three peers running, then invoke `attester hydra-evidence` to ship the reply.

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-csv-hydra.toml > /tmp/verifier-csv-hydra.log 2>&1 &
./target/release/relying-party \
    --hydra-listen 127.0.0.1:7002 hydra-serve > /tmp/rp-hydra.log 2>&1 &
./target/release/attester --config config/attester-csv-hydra.toml > /tmp/attester-csv-hydra.log 2>&1 &
sleep 130

./target/release/attester --config config/attester-csv-hydra.toml \
    hydra-evidence --rp 127.0.0.1:7002
```
