# 协议层

工程中共存两条协议：gRPC（wasm 证据校验主线）与 Hydra TCP（零知识身份证明子系统）。二者独立，不共用连接。

- gRPC 契约在 `protos/attestation.proto`，通过 `tonic-build` 生成 Rust 代码，由 `protos` crate 暴露
- Hydra TCP 帧格式与消息 tag 由 `hydra-toolkit` 定义，无 IDL

## gRPC 流程

支持两种证明模式，由 `GetEvidenceRequest` 中的 `AttestationMode` 选择。

### Background-check

```
RP --GetEvidence(mode=BACKGROUND_CHECK, nonce)--> attester --AA/TEE--> evidence
RP <-(evidence, wasm_component)-- attester
RP --Verify(tee_type, nonce, evidence, wasm_component)--> verifier
RP <-(EAR JWT)-- verifier
RP 本地验签 EAR + 比对 eat_nonce == 本地 nonce
```

nonce 由 RP 生成（建议 32 字节随机）。重放窗口由 RP 持有 nonce 与 EAR 的关联负责，verifier 无状态。

### Passport

```
RP --GetEvidence(mode=PASSPORT, nonce=空)--> attester
  └─ attester 生成 nonce → 构建 evidence → 调 verifier gRPC → 拿到 EAR
RP <-(EAR JWT)-- attester
RP 本地验签 EAR + 检查 iat 有效期（5 分钟窗口）
```

passport 模式下 attester 自行生成 nonce、构建 evidence 并在内部调用 verifier。RP 直接收到 EAR，不接触 evidence，也不需要直接调用 verifier。attester 必须配置 `verifier_endpoint`。

模式选择与 tee_type 独立：`*-hydra` 路径的 wasm 证据校验依旧沿用 background-check 或 passport；hydra 零知识部分完全在 gRPC 之外的 Hydra TCP 通道完成。

## Hydra TCP 通道

三方常驻，`hydra-toolkit` 定义帧格式：

```
[u64 big-endian 长度][负载]
```

负载前 4 字节为 tag（除 verifier→attester 加密回信外，其它均携带 tag）：

| Tag | 含义 | 方向 |
|-----|------|------|
| `DEVI` | SignedDeviceClientInfor（attester 公钥 + measurement + merkle_leaf + timestamp/period + attester 签名） | attester → verifier |
| `PCTX` | 明文 PublicContext（root 列表 + verifier_pk） | verifier → attester / RP |
| `EVID` | EvidenceReply + attester 对 EvidenceReply 的签名 | attester → RP |
| （无 tag，AES-GCM 密文） | ResponseDeviceInfor + PublicContext，用 attester 公钥经 ECDH+HKDF 派生 KEK 后 AES-GCM 加密 | verifier → attester |

RP 端遇到未知 tag 会回一段 `error: ...` 字节；attester 收到 `error:` 或 `verification failed:` 前缀视为失败并断开。

完整数据流、batch 语义、持久化布局参见 [hydra.md](hydra.md)。

## gRPC 服务

| 服务 | 方法 | 调用方 | 说明 |
|---|---|---|---|
| `AttesterService` | `GetEvidence` | RP → attester | 推 nonce 收 evidence（或 passport 模式收 EAR） |
| `VerifierService` | `Verify` | RP / attester → verifier | 提交 evidence 拿 EAR（background-check 由 RP 调，passport 由 attester 调） |

各 message 字段定义见 `protos/attestation.proto`。

`VerifyRequest.wasm` 是 `oneof`，二选一：
- 首次提交：`wasm_component`（wasm 字节流）
- 后续复用：`wasm_component_id`（首次提交后 verifier 返回的稳定 ID）

## TeeType 枚举

| proto 值 | kebab 名（claims 中用） | 备注 |
|---|---|---|
| `MOCK = 1` | `mock` | 跳过真实校验 |
| `CCA = 2` | `cca` | ARM CCA |
| `CCA_HYDRA = 3` | `cca-hydra` | CCA + hydra 通道 |
| `TDX = 4` | `tdx` | Intel TDX |
| `TDX_HYDRA = 5` | `tdx-hydra` | TDX + hydra 通道 |
| `CSV = 6` | `csv` | Hygon CSV |
| `CSV_HYDRA = 7` | `csv-hydra` | CSV + hydra 通道 |
| `ITRUSTEE = 8` | `itrustee` | iTrustee |
| `VIRTCCA = 9` | `virtcca` | VirtCCA |
| `ITRUSTEE_HYDRA = 10` | `itrustee-hydra` | iTrustee + hydra 通道 |
| `VIRTCCA_HYDRA = 11` | `virtcca-hydra` | VirtCCA + hydra 通道 |

attester 配置中的 `tee_type` 为 kebab 字符串；request 中的 `tee_type` 用 proto enum 数值。attester 收到不同于自身配置的 `tee_type` 直接拒收。

`*-hydra` appraiser 与非 hydra 版本等价，只是输出 claim `tee_type` 带 `-hydra` 后缀；hydra 层身份证明由 hydra TCP 通道单独完成。

## Nonce 编码

| 用途 | 编码 |
|---|---|
| `GetEvidenceRequest.nonce` / `VerifyRequest.nonce` | 原始字节（proto `bytes`） |
| RP 端日志 / EAR `eat_nonce` | base64url no-pad 字符串 |
| CCA evidence JSON 中的 `nonce` 字段 | base64url no-pad |
| AA REST `runtime_data` 参数 | 标准 base64 |

## EAR 输出

verifier 签发的 EAR 是 ES256 JWT。顶层 claims：

```text
iss            = "unified-attestation-verifier"
iat            = unix 秒（签发时间）
exp            = unix 秒（过期时间，iat + 3600）
eat_profile    = "tag:github.com,2024:unified-attestation"
eat_nonce      = base64url(RP nonce)
tee_type       = "mock" | "cca" | "cca-hydra" | "csv" | "csv-hydra" | "tdx" | "tdx-hydra" | "itrustee" | "itrustee-hydra" | "virtcca" | "virtcca-hydra"
component_id   = wasm 组件 ID
verifier_id    = { developer: "unified-attestation" }
submods        = wasm 返回的 claims map（含 per-TEE 度量值）
trust_vector   = { instance_identity, configuration, executables }
```

RP 持有 verifier 公钥即可本地验签 + 解码 + 比对 `eat_nonce == 本地 nonce`：

```bash
relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type mock \
    --pubkey config/keys/ear_public.pem
```

`executables < 2` 视为不可信。

### Per-TEE Claims（submods 内）

CCA 路径（`cca` / `cca-hydra`）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `cca_realm_initial_measurement` | host 验证后注入 | Realm Initial Measurement（hex） |
| `cca_realm_personalization_value` | host 验证后注入 | Realm 个性化值（hex） |
| `cca_platform_instance_id` | host 验证后注入 | CCA 平台实例 ID（hex） |
| `cca_platform_implementation_id` | host 验证后注入 | CCA 平台实现 ID（hex） |
| `cca_platform_lifecycle` | host 验证后注入 | 平台安全生命周期状态：`secured` / `secured_no_debug` / `recoverable` / `not_secured` |
| `cca_platform_sw_components` | host 验证后注入 | 平台软件组件列表 |
| `nonce_bound` | wasm appraiser 校验 | nonce 绑定是否成功 |

CSV 路径（`csv` / `csv-hydra`）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `chip_id` | host 验证后注入 | 芯片序列号 |
| `measurement` | host 验证后注入 | 度量值（hex） |
| `vm_version` | host 验证后注入 | VM 固件版本号（hex） |
| `policy_nodbg` | host 验证后注入 | 策略：是否禁止调试（0/1） |
| `policy_noks` | host 验证后注入 | 策略：是否禁止密钥共享（0/1） |
| `nonce_bound` | wasm appraiser 校验 | nonce 绑定是否成功 |

TDX 路径（`tdx` / `tdx-hydra`）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `mr_td` | wasm appraiser 提取 | TD 度量值（hex） |
| `mr_seam` | wasm appraiser 提取 | SEAM 模块度量值（hex） |
| `mr_config_id` | wasm appraiser 提取 | 配置 ID（hex） |
| `report_data` | wasm appraiser 提取 | 报告数据绑定值（hex） |
| `tcb_status` | wasm appraiser 提取 | TCB 状态 |
| `advisory_ids` | wasm appraiser 提取 | 适用的安全公告 ID 列表 |
| `nonce_bound` | wasm appraiser 校验 | nonce 绑定是否成功 |

iTrustee 路径（`itrustee` / `itrustee-hydra`）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `nonce_bound` | wasm appraiser 校验 | nonce 绑定是否成功 |
| `uuid` | host 解析 report 后注入 | Trusted Application UUID |
| `ta_img` | host 解析 report 后注入 | TA 镜像度量值（hex），可选 |
| `ta_mem` | host 解析 report 后注入 | TA 内存度量值（hex），可选 |
| `hash_alg` | host 解析 report 后注入 | 哈希算法，可选 |
| `version` | host 解析 report 后注入 | TA 版本号，可选 |
| `ima_log_size` | wasm appraiser 提取 | IMA 日志大小（字节），可选 |

VirtCCA 路径（`virtcca` / `virtcca-hydra`）：

| 字段 | 来源 | 说明 |
|------|------|------|
| `nonce_bound` | wasm appraiser 校验 | nonce 绑定是否成功 |
| `token_size` | host 解析后注入 | CBOR/COSE token 大小（字节） |
| `cert_size` | host 解析后注入 | 设备证书大小（字节） |
| `ima_log_size` | wasm appraiser 提取 | IMA 日志大小（字节），可选 |
| `event_log_size` | wasm appraiser 提取 | Event 日志大小（字节），可选 |

### Trust Vector 动态赋值

`trust_vector` 不硬编码，根据验证结果动态设定：

| TEE 类型 | `instance_identity` | `configuration` | `executables` |
|---------|---------------------|-----------------|---------------|
| mock | 2 | 2 | 2 |
| CCA / CCA-Hydra | nonce_bound ? 2 : 0 | secured/secured_no_debug→2, not_secured/recoverable→1, unknown→0 | 2 |
| CSV / CSV-Hydra | nonce_bound ? 2 : 0 | 2 | 2 |
| iTrustee / iTrustee-Hydra / VirtCCA / VirtCCA-Hydra | nonce_bound ? 2 : 0 | 2 | 2 |
| TDX / TDX-Hydra | 2 | 2 | UpToDate→2, SWHardeningNeeded/ConfigurationAndSWHardeningNeeded→1, OutOfDate/Revoked→0, unknown→1 |

AR4SI 取值含义：2 = Affirming（主张可信），1 = Warning（有告警），0 = None（不可信）。

