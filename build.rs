fn main() {
    let cjson_dir = "examples/targets/cJSON";

    println!("cargo::rerun-if-changed={}/cJSON.c", cjson_dir);

    cc::Build::new() //blackbox
        .file(format!("{}/cJSON.c", cjson_dir))
        .include(cjson_dir)
        .opt_level(3)
        .compile("cjson_blackbox");

    cc::Build::new() //graybox
        .file(format!("{}/cJSON.c", cjson_dir))
        .file(format!("{}/sancov_callbacks.c", cjson_dir))
        .include(cjson_dir)
        .compiler("clang")
        .flag("-fsanitize-coverage=trace-pc-guard")
        .opt_level(3) // opti for the fuzzer to run faster
        .compile("cjson_graybox")
}
