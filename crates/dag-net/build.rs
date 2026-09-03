//! Compiles the node-protocol contract without an external toolchain.
//!
//! `protox` is a pure-Rust protobuf compiler, so a bare checkout builds with
//! nothing but cargo — the same property the committed web-console `dist/`
//! preserves for the HTTP side. The generated modules land in `OUT_DIR` and
//! are pulled in by `src/proto.rs`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/dagnet.proto");
    let fds = protox::compile(["proto/dagnet.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(fds)?;
    Ok(())
}
