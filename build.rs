fn main() {
    // 生成 Protobuf 代码
    let mut config = prost_build::Config::new();
    // config.type_attribute(".v2ray_config.Domain", "#[derive(Copy)]");
    // config.field_attribute(".v2ray_config", "#[derive(Copy)]");

    config
        .out_dir("src")
        .compile_protos(&["src/protoes/config.proto"], &["src/protoes"])
        .unwrap();

    println!("Protobuf code generated successfully");
}
