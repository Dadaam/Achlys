//! Independent canonical replay via a separately compiled dump binary.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use achlys_bridge::{DumpOracle, compile_canonical};
use achlys_protocol::TargetManifest;

struct Args {
    corpus: PathBuf,
    out: Option<PathBuf>,
    manifest: PathBuf,
}

fn parse_args() -> Args {
    let mut corpus = None;
    let mut out = None;
    let mut manifest = PathBuf::from("benchmarks/manifests/cjson-parse.toml");

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut need = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} requires a value")))
        };
        match arg.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(need("--corpus"))),
            "--out" => out = Some(PathBuf::from(need("--out"))),
            "--manifest" => manifest = PathBuf::from(need("--manifest")),
            "-h" | "--help" => {
                eprintln!("achlys_oracle --corpus DIR --manifest PATH [--out FILE]");
                process::exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }
    let Some(corpus) = corpus else {
        die("--corpus DIR is required");
    };
    Args {
        corpus,
        out,
        manifest,
    }
}

fn die(msg: &str) -> ! {
    eprintln!("achlys_oracle: {msg}");
    process::exit(2);
}

fn list_corpus(dir: &Path) -> Vec<PathBuf> {
    if !dir.is_dir() {
        die(&format!("corpus is not a directory: {}", dir.display()));
    }
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| die(&format!("read {}: {e}", dir.display())));
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| match entry {
            Ok(e) => {
                let path = e.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let skip = name.starts_with('.') || name.ends_with(".metadata");
                (path.is_file() && !skip).then_some(path)
            }
            Err(e) => die(&format!("read {}: {e}", dir.display())),
        })
        .collect();
    files.sort();
    files
}

fn main() {
    let args = parse_args();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = if args.manifest.is_absolute() {
        args.manifest.clone()
    } else {
        root.join(&args.manifest)
    };
    let manifest = TargetManifest::from_path(&manifest_path)
        .unwrap_or_else(|e| die(&format!("manifest {}: {e}", manifest_path.display())));

    let build_dir = std::env::temp_dir().join(format!(
        "achlys_oracle_build_{}_{}",
        std::process::id(),
        manifest.target_id
    ));
    let art = compile_canonical(&root, &manifest, &build_dir, &[])
        .unwrap_or_else(|e| die(&format!("canonical compile: {e:#}")));
    let mut oracle = DumpOracle::new(&art.path, art.identity.build_id)
        .unwrap_or_else(|e| die(&format!("oracle: {e:#}")));

    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut replayed = 0usize;
    for path in list_corpus(&args.corpus) {
        let bytes =
            fs::read(&path).unwrap_or_else(|e| die(&format!("read {}: {e}", path.display())));
        let admission = oracle
            .replay(&bytes)
            .unwrap_or_else(|e| die(&format!("replay {}: {e}", path.display())));
        replayed += 1;
        if admission.admitted {
            admitted += 1;
        } else {
            rejected += 1;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>");
        println!(
            "ORACLE_INPUT file={name} admitted={} new_edges={} total_edges={} digest={}",
            admission.admitted,
            admission.new_edges,
            admission.total_edges,
            admission.digest.to_hex()
        );
    }

    let report = oracle.report(admitted, rejected, replayed);
    println!(
        "ORACLE_RESULT target={} replayed={} admitted={} rejected={} edges={} digest={} canonical_build={}",
        manifest.target_id,
        report.replayed,
        report.admitted,
        report.rejected,
        report.edge_count,
        report.digest.to_hex(),
        art.identity.build_id.to_hex()
    );

    if let Some(out) = args.out {
        if let Some(parent) = out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let body = serde_json::json!({
            "target": manifest.target_id,
            "replayed": report.replayed,
            "admitted": report.admitted,
            "rejected": report.rejected,
            "edges": report.edge_count,
            "digest": report.digest.to_hex(),
            "canonical_build": art.identity.build_id.to_hex(),
            "artifact_hash": art.identity.artifact_hash,
        });
        fs::write(&out, format!("{body}\n"))
            .unwrap_or_else(|e| die(&format!("write {}: {e}", out.display())));
    }
}
