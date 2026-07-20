fn main() {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["attestation.proto"], &["."])
        .expect("compile attestation.proto");
}
