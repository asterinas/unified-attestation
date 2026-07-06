# tee-evidence

Minimal evidence generator extracted from `attestation-agent/attester`.

Kept attester backends:

- `itrustee`
- `virtcca`
- `csv_user`
- `csv_kernel`


Run one backend at a time. The command writes `evidence.json` in this
directory.

```bash
cargo run --features virtcca-attester
cargo run --features itrustee-attester
cargo run --features csv-user-attester
cargo run --features csv-kernel-attester
```

