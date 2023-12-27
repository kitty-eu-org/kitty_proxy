fn main() {
    // 生成 Protobuf 代码
    prost_build::Config::new()
        .out_dir("src")
        .compile_protos(&["src/protoes/config.proto"], &["src/protoes"])
        .unwrap();

    println!("Protobuf code generated successfully");
}
