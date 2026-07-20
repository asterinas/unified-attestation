# Configuration Reference

Configuration keys for each binary. Common templates are available under `config/`: copy and rename.

## verifier

| key | default | description |
|---|---|---|
| `listen` | — | gRPC listen address, e.g. `127.0.0.1:8080` |
| `wasm.allow_unsigned` | `false` | Debug escape hatch; must be `false` in production |
| `wasm.registry_dir` | `data/components` | Persistent directory for registered components |
| `wasm.trusted_component_hashes` | `[]` | Trusted component sha256 whitelist (lowercase hex) |
| `ear.signing_key_path` | — | EAR JWT signing private key (PEM, ES256) |
| `policy.cca.ta_store` | — | ccatoken trust anchor store JSON path |
| `policy.cca.rv_store` | — | reference value store JSON path |
| `policy.cca.trusted_subjects` | `[]` | Trusted realm subject whitelist |
| `policy.cca.trusted_rim_hex` | `[]` | Trusted Realm Initial Measurement list (hex) |
| `policy.csv.enabled` | `false` | Enable host-side CSV verification |
| `policy.csv.cert_dir` | `/opt/hygon/csv` | HSK/CEK offline cache directory |
| `policy.csv.allow_kds_fetch` | `false` | Fetch from KDS online when cache misses |
| `policy.csv.trusted_chip_ids` | `[]` | Trusted chip_id whitelist |
| `policy.tdx.pccs_url` | `https://api.trustedservices.intel.com` | Host-side PCCS/PCS URL for fetching collateral by fmspc |
| `policy.tdx.trusted_mr_td_hex` | `[]` | Trusted mr_td list |
| `policy.tdx.trusted_mr_seam_hex` | `[]` | Trusted SEAM measurement |
| `policy.tdx.trusted_mr_config_id_hex` | `[]` | init_data_hash list |
| `policy.tdx.accept_tcb_status` | `[]` | Accepted TCB status values |
| `hydra.listen` | `127.0.0.1:7001` | hydra TCP daemon listen address |
| `hydra.data_dir` | `workspace-data/verifier` | hydra data directory (`verifier_key.bin`, cached ResponseDeviceInfor) |
| `hydra.relying_party_addrs` | `[]` | PublicContext broadcast targets; empty = do not broadcast |

When `wasm.allow_unsigned = false`, `trusted_component_hashes` must have at least one entry, otherwise the verifier will fail to start. After a new build, use `sha256sum target/wasm32-wasip1/release/*.wasm` to update the whitelist.

When policy `*_hex` lists are all empty, the corresponding policy check is skipped. In production deployments, at minimum:

- CCA / CCA-hydra: `ta_store` + `rv_store` + `trusted_subjects` + `trusted_rim_hex`
- CSV / CSV-hydra: `enabled = true` + `cert_dir` (or `allow_kds_fetch = true`) + `trusted_chip_ids`
- TDX / TDX-hydra: `pccs_url` + all four `trusted_*_hex` / `accept_tcb_status` filled
- Any hydra path: `[hydra].relying_party_addrs` should list at least one RP address

Trusted shrubs roots are maintained in memory by the verifier — no config-file whitelist is required.

## attester

| key | default | description |
|---|---|---|
| `listen` | — | attester gRPC listen address, e.g. `127.0.0.1:9000` |
| `tee_type` | — | `mock` / `cca` / `cca-hydra` / `csv` / `csv-hydra` / `tdx` / `tdx-hydra` / `itrustee` / `itrustee-hydra` / `virtcca` / `virtcca-hydra` |
| `wasm_component_path` | — | Local wasm component path |
| `aa_endpoint` | `http://127.0.0.1:8006` | guest-components api-server-rest address (non-mock paths) |
| `verifier_endpoint` | — | Verifier gRPC address (e.g. `127.0.0.1:8080`); required for passport mode |
| `hydra.verifier_addr` | — | Required when the `[hydra]` section is present; e.g. `127.0.0.1:7001` |
| `hydra.data_dir` | `workspace-data/attester` | attester data directory (`attester_key.bin` + session dirs) |
| `hydra.relying_party_addrs` | `[]` | Default RP list used by `hydra-evidence` when `--rp` is not passed |

If the `[hydra]` section is absent, no hydra client task is spawned. Non-hydra paths do not need `[hydra]`.

## relying-party (CLI)

| Flag | Description |
|---|---|
| `--attester <url>` | attester gRPC address, e.g. `http://127.0.0.1:9000` |
| `--verifier <url>` | verifier gRPC address, e.g. `http://127.0.0.1:8080` |
| `--tee-type <kebab>` | Must match attester config |
| `--pubkey <path>` | verifier EAR JWT ES256 public key (PEM) |
| `--mode <mode>` | `background-check` (default) or `passport` |
| `--ear-out <path>` | Optional; save the EAR to a file |
| `--hydra-listen <addr>` | Optional; enable the hydra TCP listener, e.g. `127.0.0.1:7002` |
| `--hydra-data-dir <path>` | Default `workspace-data/relying-party`; PublicContext cache location |
| subcommand `hydra-serve` | Only run the hydra listener, skip the gRPC flow; `--hydra-listen` is the listen address |

## attester subcommands

| Command | Description |
|---|---|
| `attester` | Default: run gRPC + hydra client (auto-bootstraps a session, does not auto-ship EvidenceReply) |
| `attester hydra-evidence [--session <path>] [--rp <addr>]...` | Build an EvidenceReply from a session and ship it; `--session` defaults to the latest session; `--rp` defaults to `[hydra].relying_party_addrs` |

## Template Reference

| Files | Usage | tee_type |
|---|---|---|
| `verifier.toml` / `attester.toml` | mock mode | `mock` |
| `verifier-cca.toml` / `attester-cca.toml` | CCA-only | `cca` |
| `verifier-cca-hydra.toml` / `attester-cca-hydra.toml` | CCA + hydra | `cca-hydra` |
| `verifier-csv.toml` / `attester-csv.toml` | Hygon CSV | `csv` |
| `verifier-csv-hydra.toml` / `attester-csv-hydra.toml` | CSV + hydra | `csv-hydra` |
| `verifier-tdx.toml` / `attester-tdx.toml` | TDX | `tdx` |
| `verifier-tdx-hydra.toml` / `attester-tdx-hydra.toml` | TDX + hydra | `tdx-hydra` |
| `verifier-itrustee.toml` / `attester-itrustee.toml` | iTrustee | `itrustee` |
| `verifier-itrustee-hydra.toml` / `attester-itrustee-hydra.toml` | iTrustee + hydra | `itrustee-hydra` |
| `verifier-virtcca.toml` / `attester-virtcca.toml` | VirtCCA | `virtcca` |
| `verifier-virtcca-hydra.toml` / `attester-virtcca-hydra.toml` | VirtCCA + hydra | `virtcca-hydra` |
