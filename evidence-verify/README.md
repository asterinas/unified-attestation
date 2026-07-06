# evidence-verify

Verifier for `tee-evidence/evidence.json`.

The verifier reads the `request` field from `evidence.json` and uses
`request.challenge` as the nonce/challenge input for evidence verification.
The `evidence` field can be either the raw JSON string produced by the library
or the expanded JSON object written by `tee-evidence/src/main.rs`.

The command-line verifier prints a JSON boolean result only:

- `true`: verification succeeded.
- `false`: reading, parsing, or verification failed.

Run from this directory:

```bash
cd evidence-verify
cargo run --features itrustee-verifier -- ../tee-evidence/evidence.json
cargo run --features virtcca-verifier -- ../tee-evidence/evidence.json
cargo run --features "virtcca-verifier no_as" -- ../tee-evidence/evidence.json
cargo run --features csv-user-verifier -- ../tee-evidence/evidence.json
cargo run --features csv-kernel-verifier -- ../tee-evidence/evidence.json
```

If no path is supplied, the default input is:

```text
../tee-evidence/evidence.json
```

Supported backends:

- `itrustee-verifier`: verifies iTrustee report authenticity with the native
  `teeverifier` library and the iTrustee reference value file.
- `virtcca-verifier`: verifies VirtCCA token signatures, certificate chain,
  challenge binding, and optional event log.
- `no_as`: uses local verifier reference paths under
  `/etc/attestation/attestation-agent/local_verifier/...` instead of
  attestation-service paths.
- `csv-user-verifier` / `csv-kernel-verifier`: verify Hygon CSV evidence from
  the user-mode or kernel-assisted attester paths. Both modes share the same
  report verification logic and differ only in the expected `evidence.mode`.
- `ima-verifier`: optional IMA verification for evidence files that contain
  `ima_log`.

Reference files and certificates use the same paths as the extracted
`attestation-service/verifier` code, for example `/etc/attestation/...`.

## Huawei VirtCCA

Use the default attestation-service paths:

```bash
cargo run --features virtcca-verifier -- ../tee-evidence/evidence.json
```

Use local verifier paths:

```bash
cargo run --features "virtcca-verifier no_as" -- ../tee-evidence/evidence.json
```

With `no_as`, the local RIM reference file is:

```text
/etc/attestation/attestation-agent/local_verifier/virtcca/ref_value.json
```

The file format is:

```json
{
  "rim": "<expected vcca.cvm.rim hex>"
}
```

If verification fails with:

```text
expecting rim: <expected>, got: <actual>
```

then the evidence RIM does not match the reference value. Update the reference
only if the current platform state is trusted.

VirtCCA certificate files are read from one of these directories:

```text
/etc/attestation/attestation-service/verifier/virtcca/
/etc/attestation/attestation-agent/local_verifier/virtcca/   # with no_as
```

Expected certificate filenames include:

```text
Huawei Equipment Root CA.pem
Huawei IT Product CA.pem
eccp521_root_cert.pem
eccp521_sub_cert.pem
```

If `evidence.json` contains `event_log`, the verifier also reads an event
reference file:

```text
/etc/attestation/attestation-service/verifier/virtcca/event/digest_list_file
/etc/attestation/attestation-agent/local_verifier/virtcca/event/digest_list_file   # with no_as
```

This file contains one trusted event digest per line.

## Huawei iTrustee

```bash
cargo run --features itrustee-verifier -- ../tee-evidence/evidence.json
```

iTrustee verification links the native library:

```text
libteeverifier.so
```

Make sure the runtime linker can find it:

```bash
export LD_LIBRARY_PATH=/path/to/libteeverifier:$LD_LIBRARY_PATH
```

The iTrustee reference value file is selected by the UUID inside the evidence:

```text
/etc/attestation/attestation-service/verifier/itrustee/itrustee_<uuid>
```

## Hygon CSV

CSV verification is adapted from the Hygon attestation demo:

- Parse `struct csv_attestation_report`.
- Recover `mnonce`, user data, measurement, PEK cert, and chip id with
  `report.anonce`, matching the C code.
- Recompute the nonce from `evidence.request.challenge` as
  `sha256(challenge)[0..16]`.
- Check both `evidence.nonce` and recovered report `mnonce`.
- Verify the report session MAC with HMAC-SM3 when the report still contains
  the original `reserved2` bytes. `tee-evidence` verifies the MAC before export
  and then clears `reserved2`, so exported reports normally mark
  `csv.session_mac` as `false` instead of failing.
- Verify the report signature with the embedded PEK public key using SM2/SM3.
- Verify the Hygon certificate chain with the same layout as the official
  Hygon devkit: the HRK public key is embedded in the verifier, HSK/CEK are
  loaded from `hsk_cek.cert`, `HYGON_HSK_CEK_CERT`, or
  `/opt/hygon/demo/csv/hsk_cek/{chip_id}/hsk_cek.cert`, and PEK is read from
  the report. If no local HSK/CEK file exists, the verifier tries
  `https://cert.hygon.cn/hsk_cek?snumber={chip_id}` with `curl`. Set
  `HYGON_CSV_DOWNLOAD_CERTS=0` to disable that network fallback.

The SM2/SM3 operations require an OpenSSL/GmSSL installation with SM3 support.
The verifier implements the SM2 verification formula directly and does not
link to `SM2_compute_message_digest` or `SM2_do_verify`.
