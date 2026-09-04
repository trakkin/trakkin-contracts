use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let adapter_proto = proto_root.join("trakkin/adapter/v1/adapter.proto");
    let bootstrap_proto = proto_root.join("trakkin/bootstrap/v1/bootstrap.proto");
    let descriptor_path = PathBuf::from(env::var("OUT_DIR")?).join("trakkin_adapter.bin");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    unsafe { env::set_var("PROTOC", protoc) };

    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .type_attribute(
            "trakkin.bootstrap.v1.LaunchRequest",
            "#[derive(serde::Deserialize, serde::Serialize)]\n#[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "trakkin.bootstrap.v1.ReadyMessage",
            "#[derive(serde::Deserialize, serde::Serialize)]\n#[serde(rename_all = \"camelCase\")]",
        )
        .compile_protos(&[adapter_proto, bootstrap_proto], &[proto_root])?;

    println!("cargo:rerun-if-changed=proto/trakkin");
    Ok(())
}
