# 配置参考

各 binary 的配置文件键值。常用模板均放在 `config/`：复制改名即可。

## verifier

| key | 默认值 | 说明 |
|---|---|---|
| `listen` | — | gRPC 监听地址，例 `127.0.0.1:8080` |
| `wasm.allow_unsigned` | `false` | 调试逃生通道；生产必须 `false` |
| `wasm.registry_dir` | `data/components` | 已注册组件持久化目录 |
| `wasm.trusted_component_hashes` | `[]` | 受信任组件 sha256 白名单（小写 hex） |
| `ear.signing_key_path` | — | EAR JWT 签名私钥（PEM, ES256） |
| `policy.cca.ta_store` | — | ccatoken trust anchor store JSON 路径 |
| `policy.cca.rv_store` | — | reference value store JSON 路径 |
| `policy.cca.trusted_subjects` | `[]` | 可信 realm 主体白名单 |
| `policy.cca.trusted_rim_hex` | `[]` | 可信 Realm Initial Measurement 列表（hex） |
| `policy.csv.enabled` | `false` | 是否启用 host 端 CSV 验签 |
| `policy.csv.cert_dir` | `/opt/hygon/csv` | HSK/CEK 离线缓存目录 |
| `policy.csv.allow_kds_fetch` | `false` | 离线未命中时是否走 KDS 在线拉取 |
| `policy.csv.trusted_chip_ids` | `[]` | 可信 chip_id 白名单 |
| `policy.tdx.pccs_url` | `https://api.trustedservices.intel.com` | host 端按 fmspc 拉 collateral 用 |
| `policy.tdx.trusted_mr_td_hex` | `[]` | 可信 mr_td 列表 |
| `policy.tdx.trusted_mr_seam_hex` | `[]` | 可信 SEAM 测量 |
| `policy.tdx.trusted_mr_config_id_hex` | `[]` | init_data_hash 列表 |
| `policy.tdx.accept_tcb_status` | `[]` | 接受的 TCB status |
| `hydra.listen` | `127.0.0.1:7001` | hydra TCP daemon 监听地址 |
| `hydra.data_dir` | `workspace-data/verifier` | hydra 数据目录（`verifier_key.bin`、缓存 ResponseDeviceInfor） |
| `hydra.relying_party_addrs` | `[]` | PublicContext 广播目标 TCP 列表；为空则不广播 |

`wasm.allow_unsigned = false` 时，`trusted_component_hashes` 必须至少配一项，
否则 verifier 启动失败。新 build 后用 `sha256sum target/wasm32-wasip1/release/*.wasm`
更新白名单。

policy 的 `*_hex` 列表均空 → 对应 policy 跳过。生产部署中至少：

- CCA / CCA-hydra：`ta_store` + `rv_store` + `trusted_subjects` + `trusted_rim_hex`
- CSV / CSV-hydra：`enabled = true` + `cert_dir`（或 `allow_kds_fetch = true`） + `trusted_chip_ids`
- TDX / TDX-hydra：`pccs_url` + 四项 `trusted_*_hex` / `accept_tcb_status` 全填
- 任一 hydra 路径：`[hydra].relying_party_addrs` 至少一条 RP 地址

hydra 的可信 root 由 verifier 内存维护，无需配置文件白名单。

## attester

| key | 默认值 | 说明 |
|---|---|---|
| `listen` | — | attester gRPC 监听地址，例 `127.0.0.1:9000` |
| `tee_type` | — | `mock` / `cca` / `cca-hydra` / `csv` / `csv-hydra` / `tdx` / `tdx-hydra` / `itrustee` / `itrustee-hydra` / `virtcca` / `virtcca-hydra` |
| `wasm_component_path` | — | 本地 wasm 组件路径 |
| `aa_endpoint` | `http://127.0.0.1:8006` | guest-components api-server-rest 地址（非 mock 路径） |
| `verifier_endpoint` | — | Verifier gRPC 地址（例 `127.0.0.1:8080`），passport 模式必填 |
| `hydra.verifier_addr` | — | hydra 段存在时必填；例 `127.0.0.1:7001` |
| `hydra.data_dir` | `workspace-data/attester` | attester 数据目录（`attester_key.bin` + session 目录） |
| `hydra.relying_party_addrs` | `[]` | `hydra-evidence` 子命令未传 `--rp` 时的默认 RP 列表 |

`[hydra]` 整段缺省时不启动 hydra client task；非 hydra 路径无需 `[hydra]`。

## relying-party（CLI）

| 参数 | 说明 |
|---|---|
| `--attester <url>` | attester gRPC 地址，例 `http://127.0.0.1:9000` |
| `--verifier <url>` | verifier gRPC 地址，例 `http://127.0.0.1:8080` |
| `--tee-type <kebab>` | 与 attester 配置一致的 tee_type |
| `--pubkey <path>` | verifier EAR JWT 的 ES256 公钥（PEM） |
| `--mode <mode>` | `background-check`（默认）或 `passport` |
| `--ear-out <path>` | 可选，保存 EAR 到文件 |
| `--hydra-listen <addr>` | 可选，启用 hydra TCP listener，例 `127.0.0.1:7002` |
| `--hydra-data-dir <path>` | 默认 `workspace-data/relying-party`；PublicContext 缓存位置 |
| 子命令 `hydra-serve` | 只启 hydra 监听、不跑 gRPC 证明流；`--hydra-listen` 作为监听地址 |

## attester 子命令

| 命令 | 说明 |
|---|---|
| `attester` | 默认：常驻 gRPC + hydra client（自动 bootstrap session，不主动发 EvidenceReply） |
| `attester hydra-evidence [--session <path>] [--rp <addr>]...` | 从 session 生成 EvidenceReply 并投递；`--session` 缺省用最近一次；`--rp` 缺省用 `[hydra].relying_party_addrs` |

## 模板对照

| 文件 | 用途 | tee_type |
|---|---|---|
| `verifier.toml` / `attester.toml` | mock 模式 | `mock` |
| `verifier-cca.toml` / `attester-cca.toml` | CCA-only | `cca` |
| `verifier-cca-hydra.toml` / `attester-cca-hydra.toml` | CCA + hydra 叠加 | `cca-hydra` |
| `verifier-csv.toml` / `attester-csv.toml` | Hygon CSV | `csv` |
| `verifier-csv-hydra.toml` / `attester-csv-hydra.toml` | CSV + hydra 叠加 | `csv-hydra` |
| `verifier-tdx.toml` / `attester-tdx.toml` | TDX | `tdx` |
| `verifier-tdx-hydra.toml` / `attester-tdx-hydra.toml` | TDX + hydra 叠加 | `tdx-hydra` |
| `verifier-itrustee.toml` / `attester-itrustee.toml` | iTrustee | `itrustee` |
| `verifier-itrustee-hydra.toml` / `attester-itrustee-hydra.toml` | iTrustee + hydra 叠加 | `itrustee-hydra` |
| `verifier-virtcca.toml` / `attester-virtcca.toml` | VirtCCA | `virtcca` |
| `verifier-virtcca-hydra.toml` / `attester-virtcca-hydra.toml` | VirtCCA + hydra 叠加 | `virtcca-hydra` |
