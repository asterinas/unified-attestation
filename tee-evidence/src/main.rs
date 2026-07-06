use anyhow::{Context, Result};
use std::fs;
use tee_evidence::{default_evidence_request, Attester};

fn main() -> Result<()> {
    let evidence = Attester
        .tee_get_evidence(default_evidence_request())
        .context("get TEE evidence failed")?;

    let mut evidence_json: serde_json::Value =
        serde_json::from_slice(&evidence).context("evidence is not valid JSON")?;

    if let Some(evidence_field) = evidence_json.get_mut("evidence") {
        if let Some(evidence_str) = evidence_field.as_str() {
            if let Ok(inner_json) = serde_json::from_str::<serde_json::Value>(evidence_str) {
                *evidence_field = inner_json;
            }
        }
    }

    let output = serde_json::to_string(&evidence_json)?;
    fs::write("evidence.json", &output).context("write evidence.json failed")?;
    println!("{output}");

    Ok(())
}
