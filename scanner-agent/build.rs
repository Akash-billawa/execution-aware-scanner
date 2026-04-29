fn main() {
    println!("cargo:rerun-if-changed=proto/remediator.proto");

    // Skip proto generation if SKIP_PROTO is set (for CI without protoc)
    if std::env::var("SKIP_PROTO").is_ok() {
        println!("cargo:warning=Skipping protobuf generation (SKIP_PROTO set)");
        return;
    }

    // Try to compile protobuf
    match tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/remediator.proto"], &["proto"])
    {
        Ok(_) => println!("cargo:warning=Protobuf compiled successfully"),
        Err(e) => {
            println!("cargo:warning=Failed to compile protobuf: {e}");
            println!("cargo:warning=Continuing without protobuf support");
        }
    }
}
