# 操作手册

构建、运行、调试用的命令清单。

## 前置依赖

- Rust 1.90.0（见 `rust-toolchain.toml`）
- `cargo install cargo-component --locked`（编 wasm appraiser 用）
- `rustup target add wasm32-wasip1`
- `openssl`（生成 ES256 密钥对）

## 通用脚本

| 脚本 | 用途 | 依赖 |
| ---- | ---- | ---- |
| `scripts/run-mvp.sh` | mock 模式端到端（无 TEE 依赖） | — |
| `scripts/gen-keys.sh` | 生成 ES256 密钥对到 `config/keys/` | openssl |
| `scripts/build-appraisers.sh` | 编译所有 wasm appraiser | cargo-component, wasm32-wasip1 |

`config/keys/` 由脚本生成，已加入 `.gitignore`。

各 TEE 端到端测试步骤需在对应硬件环境下手动执行，命令清单见分文档：

- CCA / CCA + hydra：[cca.md](cca.md)
- Hygon CSV / CSV + hydra：[csv.md](csv.md)
- TDX / TDX + hydra：[tdx.md](tdx.md)
- iTrustee / iTrustee + hydra：[itrustee.md](itrustee.md)
- VirtCCA / VirtCCA + hydra：[virtcca.md](virtcca.md)

### iTrustee 端到端测试

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-itrustee.toml > /tmp/verifier-itrustee.log 2>&1 &
./target/release/attester --config config/attester-itrustee.toml > /tmp/attester-itrustee.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type itrustee \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-itrustee.jwt
```

### VirtCCA 端到端测试

```bash
bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh
cargo build --release -p verifier -p attester -p relying-party

ttrpc-aa &
api-server-rest --features attestation &

./target/release/verifier --config config/verifier-virtcca.toml > /tmp/verifier-virtcca.log 2>&1 &
./target/release/attester --config config/attester-virtcca.toml > /tmp/attester-virtcca.log 2>&1 &
sleep 2

./target/release/relying-party \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type virtcca \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-virtcca.jwt
```

## Passport 模式

在 relying-party 上通过 `--mode passport` 启用。attester 必须配置 `verifier_endpoint` 以便内部调用 verifier。此模式下 RP 直接从 attester 收到 EAR，不再调用 verifier。

Passport 与 hydra 独立：passport 只影响 gRPC 的 wasm 证据流；hydra 走独立 TCP 长连接子系统，见 [hydra.md](hydra.md)。

```bash
./target/release/verifier --config config/verifier.toml > /tmp/verifier.log 2>&1 &
./target/release/attester --config config/attester.toml > /tmp/attester.log 2>&1 &
sleep 2

./target/release/relying-party \
    --mode passport \
    --attester http://127.0.0.1:9000 \
    --tee-type mock \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear-passport.jwt
```

RP 验证 EAR 签名和有效期（iat 在 5 分钟内），不比对 eat_nonce。

## Hydra 模式

需三方常驻并保持 TCP 长连接：

```bash
# 1. 启动 verifier（config/verifier-cca-hydra.toml 里已包含 [hydra] 段）
./target/release/verifier --config config/verifier-cca-hydra.toml > /tmp/verifier-hydra.log 2>&1 &

# 2. 启动 relying-party，加 --hydra-listen 打开 TCP 监听
./target/release/relying-party \
    --hydra-listen 127.0.0.1:7002 \
    --hydra-data-dir workspace-data/relying-party \
    hydra-serve > /tmp/rp-hydra.log 2>&1 &

# 3. 启动 attester，config 里含 [hydra] 段就会自动 bootstrap
./target/release/attester --config config/attester-cca-hydra.toml > /tmp/attester-hydra.log 2>&1 &
sleep 130   # 至少一个 batch 窗口（默认 120s）

# 4. 一次性生成 EvidenceReply 并投递
./target/release/attester --config config/attester-cca-hydra.toml \
    hydra-evidence --rp 127.0.0.1:7002
```

关键路径：

| 文件 | 作用 |
| ---- | ---- |
| `workspace-data/verifier/verifier_key.bin` | verifier 密钥（丢失即已发出的 EvidenceReply 均不可验） |
| `workspace-data/attester/attester_key.bin` | attester 密钥 |
| `workspace-data/attester/attester_latest_session.txt` | `hydra-evidence` 缺省读取的最近 session 指针 |
| `workspace-data/attester/attester-runs/attester-<time>-<pid>-<counter>/` | 单次会话（dev_infor / dev_res / dev_config / public_context） |
| `workspace-data/relying-party/public_context.bin` | RP 缓存的 PublicContext（重启后自动加载） |

## 工具

| 命令 | 用途 |
| ---- | ---- |
| `sha256sum target/wasm32-wasip1/release/*.wasm` | 计算 appraiser sha256（更新白名单用） |
