use std::io::Result;

fn main() -> Result<()> {
    // Tell cargo to recompile if proto files change
    println!("cargo:rerun-if-changed=proto/remediator.proto");
    
    // Only generate protobuf code if proto file exists
    if std::path::Path::new("proto/remediator.proto").exists() {
        tonic_build::configure()
            .build_server(false)
            .compile(&["proto/remediator.proto"], &["proto"])?;
    }
    
    Ok(())
}
