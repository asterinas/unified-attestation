//! Wasm component loading, sha256 whitelist validation, and sandbox invocation.

use crate::config::Config;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

// Generate wasm component bindings from the WIT interface definition
wasmtime::component::bindgen!({
    path: "../appraisers/wit",
    world: "verifier",
    exports: { default: async },
});

use exports::unified_attestation::verifier::verifier_interface::OptionalData;

/// Wasm component host: manages whitelist validation, registration, compilation, and sandbox calls.
///
/// Registration flow: sha256 whitelist check → compile → persist to registry_dir → memory cache.
/// Components with the same sha256 are compiled only once; subsequent requests reuse the cached instance.
pub struct WasmHost {
    /// wasmtime engine, shared globally across all requests
    engine: Engine,
    /// Debug escape hatch: when true, skip sha256 whitelist check (development only)
    allow_unsigned: bool,
    /// Persistent directory for registered component binaries
    registry_dir: PathBuf,
    /// Trusted component sha256 hashes (lowercase hex). Enforced when allow_unsigned=false.
    trusted_hashes: HashSet<String>,
    /// In-memory registry: sha256 → component_id → compiled component, RwLock-protected
    registry: RwLock<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    /// component_id -> sha256 hex
    by_id: HashMap<String, String>,
    /// sha256 hex -> component_id
    by_hash: HashMap<String, String>,
    /// component_id -> pre-compiled wasmtime Component
    compiled: HashMap<String, Component>,
}

pub struct EvaluateOutcome {
    pub component_id: String,
    pub claims: Value,
}

impl WasmHost {
    pub async fn new(config: &Config) -> Result<Arc<Self>> {
        // Ensure persistent registry directory exists
        tokio::fs::create_dir_all(&config.wasm.registry_dir)
            .await
            .with_context(|| format!("create {}", config.wasm.registry_dir.display()))?;

        let mut wasmtime_cfg = wasmtime::Config::new();
        wasmtime_cfg.wasm_component_model(true);
        wasmtime_cfg.async_support(true);
        let engine = Engine::new(&wasmtime_cfg).context("create wasmtime engine")?;

        // Trust anchor: mutually-exclusive guard between allow_unsigned and trusted_hashes.
        // Prevents the misconfiguration of "unsigned disabled but no hashes configured"
        // (rejects everything) or the opposite "unsigned enabled plus hashes" (pointless).
        if !config.wasm.allow_unsigned && config.wasm.trusted_component_hashes.is_empty() {
            anyhow::bail!("wasm: allow_unsigned=false requires at least one trusted_component_hashes");
        }
        if config.wasm.allow_unsigned {
            warn!(
                "wasm component signature verification disabled (allow_unsigned = true). \
                 do not enable in production"
            );
        }

        let trusted_hashes: HashSet<String> = config
            .wasm
            .trusted_component_hashes
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        if !trusted_hashes.is_empty() {
            info!(
                trusted_count = trusted_hashes.len(),
                "wasm trusted_component_hashes loaded"
            );
        }

        Ok(Arc::new(Self {
            engine,
            allow_unsigned: config.wasm.allow_unsigned,
            registry_dir: config.wasm.registry_dir.clone(),
            trusted_hashes,
            registry: RwLock::new(RegistryState::default()),
        }))
    }

    /// Register (or reuse) a component, returning its stable component_id.
    ///
    /// Registration flow:
    /// 1. Compute sha256 of the raw wasm bytes
    /// 2. Whitelist check (unless allow_unsigned)
    /// 3. Check registry cache — if already registered by sha256, return existing id
    /// 4. Compile the wasm component
    /// 5. Persist to disk (for cross-restart reuse)
    /// 6. Acquire write lock — check again for race, register if still novel
    pub async fn register(&self, component_bytes: &[u8]) -> Result<String> {
        let sha = sha256_hex(component_bytes);
        // Enforce whitelist unless the escape hatch is open
        if !self.allow_unsigned && !self.trusted_hashes.contains(&sha) {
            bail!("untrusted wasm component: sha256={sha}");
        }
        // Fast path: check cache under read lock
        {
            let state = self.registry.read().await;
            if let Some(id) = state.by_hash.get(&sha) {
                return Ok(id.clone());
            }
        }

        let component = Component::from_binary(&self.engine, component_bytes)
            .context("compile wasm component")?;
        // Generate a new stable ID and persist the component to disk
        let id = Uuid::new_v4().to_string();
        let path = self.registry_dir.join(format!("{id}.wasm"));
        tokio::fs::write(&path, component_bytes)
            .await
            .with_context(|| format!("persist {}", path.display()))?;

        // Write-lock: check for concurrent registration race.
        // If another request registered the same sha256 while we were compiling,
        // discard our duplicate and reuse the winner's id.
        let mut state = self.registry.write().await;
        if let Some(existing) = state.by_hash.get(&sha).cloned() {
            drop(state);
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(existing);
        }
        state.by_id.insert(id.clone(), sha.clone());
        state.by_hash.insert(sha, id.clone());
        state.compiled.insert(id.clone(), component);
        info!(component_id = %id, "registered wasm component");
        Ok(id)
    }

    /// Call the component's evaluate function and return the parsed claims JSON.
    ///
    /// Parameter semantics:
    /// - `expected_report_data`: raw challenge nonce bytes. The wasm compares this against
    ///   the binding field in evidence (CCA realm challenge, TDX report_data[..32],
    ///   hydra public_input last element).
    /// - `expected_init_data_hash`: TDX path only, compared against mr_config_id.
    ///   Other paths pass None.
    pub async fn evaluate(
        &self,
        component_id: &str,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
    ) -> Result<EvaluateOutcome> {
        // Look up the pre-compiled component
        let component = {
            let state = self.registry.read().await;
            state
                .compiled
                .get(component_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown component_id {component_id}"))?
        };

        // Set up the WASI environment within wasmtime
        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).context("add wasi to linker")?;

        let mut store = Store::new(&self.engine, HostState::new());
        let bindings = Verifier::instantiate_async(&mut store, &component, &linker)
            .await
            .context("instantiate component")?;
        let iface = bindings.unified_attestation_verifier_verifier_interface();
        let verifier = iface.verifier();
        // The component's constructor is a no-op for all appraisers currently
        let resource = verifier
            .call_constructor(&mut store)
            .await
            .context("call constructor")?;

        // Map Option<&[u8]> to WIT OptionalData enum
        let report_data = match expected_report_data {
            Some(v) => OptionalData::Value(v.to_vec()),
            None => OptionalData::NotProvided,
        };
        let init_data = match expected_init_data_hash {
            Some(v) => OptionalData::Value(v.to_vec()),
            None => OptionalData::NotProvided,
        };

        // Invoke the component's evaluate function inside the sandbox
        let raw = verifier
            .call_evaluate(&mut store, resource, evidence, &report_data, &init_data)
            .await
            .context("call evaluate")?;

        let claims: Value = serde_json::from_str(&raw)
            .with_context(|| format!("component returned non-json: {raw}"))?;
        if let Some(err) = claims.get("error") {
            bail!("wasm component reported error: {err}");
        }
        // Any verification field value other than "passed" is treated as rejection.
        // This guards against cases where verify_groth16 returns false but the component
        // doesn't explicitly set an error field.
        let verification = claims
            .get("verification")
            .and_then(|v| v.as_str())
            .unwrap_or("missing");
        if verification != "passed" {
            bail!("verification did not pass: {verification}");
        }
        Ok(EvaluateOutcome {
            component_id: component_id.to_string(),
            claims,
        })
    }
}

/// Per-store host state for wasmtime: resource table + WASI context.
struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl HostState {
    fn new() -> Self {
        // Inherit stdio so wasm components can use tracing/println for debugging
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();
        Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
        }
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Compute sha256 hex digest of raw bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
