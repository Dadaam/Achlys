fn main() {
    let cjson_dir = "examples/targets/cJSON";

    println!("cargo::rerun-if-changed={}/cJSON.c", cjson_dir);
    println!("cargo::rerun-if-changed={}/sancov_callbacks.c", cjson_dir);
    println!("cargo::rerun-if-changed=benchmarks/micro/crash_if_magic.c");

    // Graybox first: both libs export cJSON_Parse. The first linked copy wins.
    // H0 needs the SanCov-instrumented definition plus the callbacks.
    cc::Build::new()
        .file(format!("{}/cJSON.c", cjson_dir))
        .file(format!("{}/sancov_callbacks.c", cjson_dir))
        .include(cjson_dir)
        .compiler("clang")
        .flag("-fsanitize-coverage=trace-pc-guard")
        .opt_level(3)
        .compile("cjson_graybox");

    cc::Build::new()
        .file(format!("{}/cJSON.c", cjson_dir))
        .include(cjson_dir)
        .opt_level(3)
        .compile("cjson_blackbox");

    // In-process micro-target (no SanCov here: EDGES_MAP would clash with cjson_graybox).
    cc::Build::new()
        .file("benchmarks/micro/crash_if_magic.c")
        .opt_level(3)
        .compile("micro_crash_if_magic");
}
