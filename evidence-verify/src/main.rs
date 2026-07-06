use std::{env, fs, path::PathBuf};

fn main() {
    let input = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("..")
            .join("tee-evidence")
            .join("evidence.json")
    });

    let verified = fs::read(&input)
        .ok()
        .and_then(|evidence_json| evidence_verify::verify_evidence_json(&evidence_json).ok())
        .is_some();

    println!("{verified}");
}
