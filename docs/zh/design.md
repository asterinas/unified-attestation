# 设计要点

四条核心机制详细说明。README 的「核心特性」是这份文档的浓缩版。

## verifier 与 TEE 平台解耦

传统远程证明中，verifier 需要为每种 TEE 平台内置专用的 evidence 解析器和签名校验代码——新增一种 TEE，verifier 就要加一套解析逻辑和证书链校验。这意味着 TEE 平台升级（如证书格式变更、签名算法替换）必然要求 verifier 同步更新，verifier 事实上被平台绑定。

本方案将"某类 TEE 的 evidence 如何验证"这件事从 verifier 中剥离，封装成独立的 wasm 组件。attester 发起证明时，把 evidence 和对应的 wasm 验证组件一起提交给 verifier。verifier 只做三件事：

1. 检查 wasm 组件的 sha256 是否在配置的白名单中（确认组件来源可信）
2. 在 wasmtime 沙箱中调用组件的 evaluate 接口，传入 evidence 和 challenge nonce
3. 把组件返回的 claims 与本地策略（如可信 root 列表）比对

verifier 不需要理解 evidence 的内部格式，不需要知道用了什么签名算法，甚至不需要知道零知识证明的存在——这些都在 wasm 组件内部完成。TEE 平台升级只需更新 wasm 组件并重新计算 sha256 白名单，verifier 代码无需任何改动。

> 例外：CCA / CSV 验签依赖 ccatoken / csv-rs（OpenSSL），iTrustee 验签依赖 libteeverifier.so FFI，VirtCCA 验签依赖 OpenSSL + COSE/CBOR，这些库无法编译到 wasm32-wasip1。因此这四类 TEE 的真验签放在 verifier host，wasm appraiser 只做字段透传与 nonce 比对。TDX 仍走"全部进 wasm"（dcap-qvl 支持 wasm32）。

## challenge 与 proof 密码学绑定

远程证明的核心安全目标之一是阻止重放攻击：攻击者截获一份合法的 evidence 后反复提交，如果没有防护机制，verifier 会多次签发 EAR。

常见的防重放做法是在 token 中嵌入时间戳或递增计数器，但这些方案存在窗口期——时间戳在过期前仍有被重放的风险，计数器则要求双方同步状态。本方案换了一条路径：让 challenge nonce 直接参与零知识证明的约束系统，使 proof 本身与本次 nonce 在密码学上耦合。具体过程：

1. verifier 签发一个 32 字节随机 nonce 给 attester
2. attester 通过 `nonce_to_scalar = Fr::from_le_bytes_mod_order(blake2s_256(nonce))` 编码 nonce 为标量域元素，并填入 Groth16 电路作为公开输入末位，然后生成证明。此时生成的 proof 是"假定了 nonce 为某个特定值"的证明
3. wasm 验证组件在验证时，先从 evidence 中读取 proof 对应的 public_inputs，取出其中最后一个字段（即 attester 声称的 nonce 标量），再对 verifier 透传的 expected_report_data（即本次 challenge 的原始 nonce 字节）按同一算法算出标量，两者严格比对
4. 只有 Groth16 验证通过**且** nonce 比对通过，组件才返回 verification: passed

攻击者截获一份历史 evidence 后重放：proof 中的 nonce 字段对应的是旧 challenge，而 verifier 本次透传的 expected_report_data 是新 challenge 的 nonce——步骤 3 的比对必然失败。这不是时间判断，是密码学不等式，不存在绕过路径。

## 设备身份零知识证明

attester 用 Shrubs 累积器将一组设备公钥压缩成 root 列表，再用 Merkle path 证明自身在白名单中，整个过程不暴露 attestation 密钥和具体索引。verifier 仅知道证据来自某个受信任设备，无法定位到具体设备。

电路细节见 [`hydra.md`](hydra.md)。

## 三层独立信任锚

组件白名单（sha256）堵任意 wasm 上传，nonce 绑定堵证据重放，可信 root 列表堵未授权设备。三层机制互不依赖，攻击者必须同时突破三者才能拿到被签发的 EAR。

## EAR 自包含

EAR 是 ES256 签名的 JWT，签出后即可被任意持公钥的第三方独立校验，verifier 只是签发方——不依赖 verifier 在线、不需要额外网络往返。relying-party 持公钥即可本地完成验签和解码。
