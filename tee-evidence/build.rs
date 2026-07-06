use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os != "linux" || target_arch != "x86_64" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let csv_user = env::var_os("CARGO_FEATURE_CSV_USER_ATTESTER").is_some();
    let csv_kernel = env::var_os("CARGO_FEATURE_CSV_KERNEL_ATTESTER").is_some();

    assert!(
        !(csv_user && csv_kernel),
        "csv-user-attester and csv-kernel-attester must be built separately"
    );

    if csv_user {
        build_csv_backend(
            "csv_user_attestation",
            &manifest_dir.join("src/csv_user/csv_user_attestation.c"),
            &manifest_dir.join("src/csv_user"),
            &[
                "csv_user_attestation_report_size",
                "csv_user_get_attestation_report",
            ],
            false,
        );
    }

    if csv_kernel {
        build_csv_backend(
            "csv_kernel_attestation",
            &manifest_dir.join("src/csv_kernel/csv_kernel_attestation.c"),
            &manifest_dir.join("src/csv_kernel"),
            &[
                "csv_kernel_attestation_report_size",
                "csv_kernel_get_attestation_report",
            ],
            true,
        );
    }
}

fn build_csv_backend(
    lib_name: &str,
    source: &Path,
    include_dir: &Path,
    required_symbols: &[&str],
    kernel_mode: bool,
) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let object = out_dir.join(format!("{lib_name}.o"));

    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("csv_attestation.h").display()
    );
    println!("cargo:rerun-if-env-changed=CSV_GMSSL_INCLUDE");
    println!("cargo:rerun-if-env-changed=CSV_GMSSL_LIB");
    println!("cargo:rerun-if-env-changed=CSV_LIBCRYPTO_A");

    let gmssl_include =
        env::var("CSV_GMSSL_INCLUDE").unwrap_or_else(|_| "/opt/gmssl/include".to_string());
    let gmssl_lib = env::var("CSV_GMSSL_LIB").unwrap_or_else(|_| "/opt/gmssl/lib".to_string());

    let mut command = Command::new("gcc");
    command
        .arg("-Wall")
        .arg("-O2")
        .arg("-fPIC")
        .arg("-m64")
        .arg("-mrdrnd");

    if kernel_mode {
        command.arg("-fno-stack-protector");
    }

    let status = command
        .arg("-c")
        .arg(source)
        .arg("-I")
        .arg(include_dir)
        .arg("-I")
        .arg(gmssl_include)
        .arg("-o")
        .arg(&object)
        .status()
        .unwrap_or_else(|err| panic!("failed to invoke gcc for {lib_name}: {err}"));
    assert!(status.success(), "gcc failed while building {lib_name}");

    verify_symbols(lib_name, &object, required_symbols);

    println!("cargo:rustc-link-arg={}", object.display());
    if kernel_mode {
        let libcrypto_a =
            env::var("CSV_LIBCRYPTO_A").unwrap_or_else(|_| "/usr/lib/libcrypto.a".to_string());

        println!("cargo:rustc-link-arg={libcrypto_a}");
        println!("cargo:rustc-link-arg=-lc");
        println!("cargo:rustc-link-arg=-lpthread");
    } else {
        println!("cargo:rustc-link-search=native={gmssl_lib}");
        println!("cargo:rustc-link-arg=-lcrypto");
    }
}

fn verify_symbols(lib_name: &str, object: &Path, required_symbols: &[&str]) {
    let output = Command::new("nm")
        .arg("-g")
        .arg(object)
        .output()
        .unwrap_or_else(|err| panic!("failed to invoke nm for {lib_name}: {err}"));
    assert!(
        output.status.success(),
        "nm failed while checking {lib_name}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for symbol in required_symbols {
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().last() == Some(*symbol)),
            "{lib_name} did not export `{symbol}`; check that the matching C file was copied into the matching src/csv_* directory"
        );
    }
}
