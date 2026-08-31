use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let proto = proto_root.join("trakkin/adapter/v1/adapter.proto");
    let descriptor_path = PathBuf::from(env::var("OUT_DIR")?).join("trakkin_adapter.bin");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    unsafe { env::set_var("PROTOC", protoc) };

    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(&[proto], &[proto_root])?;

    println!("cargo:rerun-if-changed=proto/trakkin/adapter/v1");
    Ok(())
}
