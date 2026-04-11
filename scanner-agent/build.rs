use std::io::Result;

fn main() -> Result<()> {
    // Tell cargo to recompile if proto files change
    println!("cargo:rerun-if-changed=proto/remediator.proto");

    // Try to compile protobuf, but don't fail if protoc is not available
    // This allows builds on non-Linux environments
    let protoc_path = std::env::var("PROTOC")
        .ok()
        .or_else(|| which::which("protoc").ok().map(|p| p.to_string_lossy().to_string()));

    if protoc_path.is_some() {
        match tonic_build::compile_protos("proto/remediator.proto") {
            Ok(_) => println!("cargo:warning=Protobuf compiled successfully"),
            Err(e) => {
                println!("cargo:warning=Failed to compile protobuf: {}", e);
                println!("cargo:warning=The remediator feature will not be available");
            }
        }
    } else {
        println!("cargo:warning=protoc not found, skipping protobuf generation");
        println!("cargo:warning=The remediator feature will not be available");
    }

    Ok(())
}
