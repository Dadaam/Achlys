fn main() {
    let cjson_dir = "examples/targets/cJSON";

    println!("cargo::rerun-if-changed={}/cJSON.c", cjson_dir);

    cc::Build::new()
        .file(format!("{}/cJSON.c", cjson_dir))
        .include(cjson_dir)
        .opt_level(3) // opti for the fuzzer to run faster
        .compile("cjson")
}
