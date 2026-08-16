//! Independent canonical replay via a separately compiled dump binary.
//!
//! Compile once (`--compile-out DIR`), then replay any number of corpora
//! against that same artifact (`--binary` + `--identity`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use achlys_bridge::{DumpOracle, compile_canonical};
use achlys_protocol::{BuildIdentity, InputId, TargetManifest};

struct Args {
    corpus: Option<PathBuf>,
    out: Option<PathBuf>,
    manifest: PathBuf,
    compile_out: Option<PathBuf>,
    binary: Option<PathBuf>,
    identity: Option<PathBuf>,
    expected_files: Option<usize>,
}

fn parse_args() -> Args {
    let mut corpus = None;
    let mut out = None;
    let mut manifest = PathBuf::from("benchmarks/manifests/cjson-parse.toml");
    let mut compile_out = None;
    let mut binary = None;
    let mut identity = None;
    let mut expected_files = None;

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
            "--compile-out" => compile_out = Some(PathBuf::from(need("--compile-out"))),
            "--binary" => binary = Some(PathBuf::from(need("--binary"))),
            "--identity" => identity = Some(PathBuf::from(need("--identity"))),
            "--expected-files" => {
                expected_files = Some(
                    need("--expected-files")
                        .parse()
                        .unwrap_or_else(|_| die("--expected-files must be usize")),
                );
            }
            "-h" | "--help" => {
                eprintln!(
                    "achlys_oracle --manifest PATH [--compile-out DIR] \
                     [--binary FILE --identity FILE] [--corpus DIR] [--out FILE] \
                     [--expected-files N]"
                );
                process::exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }
    Args {
        corpus,
        out,
        manifest,
        compile_out,
        binary,
        identity,
        expected_files,
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

fn file_sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| die(&format!("hash {}: {e}", path.display())));
    InputId::from_bytes(&bytes).to_hex()
}

fn write_identity(path: &Path, identity: &BuildIdentity) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_vec_pretty(identity)
        .unwrap_or_else(|e| die(&format!("serialize identity: {e}")));
    fs::write(path, json).unwrap_or_else(|e| die(&format!("write {}: {e}", path.display())));
}

fn load_identity(path: &Path) -> BuildIdentity {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| die(&format!("read identity {}: {e}", path.display())));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| die(&format!("parse identity {}: {e}", path.display())))
}

fn resolve_artifact(args: &Args) -> (PathBuf, BuildIdentity) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match (&args.binary, &args.identity, &args.compile_out) {
        (Some(binary), Some(identity_path), _) => {
            let identity = load_identity(identity_path);
            let Some(expected) = identity.artifact_hash.as_deref() else {
                die("identity.json has no artifact_hash");
            };
            let actual = file_sha256_hex(binary);
            if actual != expected {
                die(&format!(
                    "binary hash {actual} != identity artifact_hash {expected}"
                ));
            }
            (binary.clone(), identity)
        }
        (None, None, compile_out) => {
            let manifest_path = if args.manifest.is_absolute() {
                args.manifest.clone()
            } else {
                root.join(&args.manifest)
            };
            let manifest = TargetManifest::from_path(&manifest_path)
                .unwrap_or_else(|e| die(&format!("manifest {}: {e}", manifest_path.display())));
            let build_dir = compile_out.clone().unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "achlys_oracle_build_{}_{}",
                    std::process::id(),
                    manifest.target_id
                ))
            });
            let art = compile_canonical(&root, &manifest, &build_dir, &[])
                .unwrap_or_else(|e| die(&format!("canonical compile: {e:#}")));
            let id_path = build_dir.join("identity.json");
            write_identity(&id_path, &art.identity);
            println!(
                "ORACLE_COMPILE path={} identity={} canonical_build={} artifact_hash={}",
                art.path.display(),
                id_path.display(),
                art.identity.build_id.to_hex(),
                art.identity.artifact_hash.as_deref().unwrap_or("-")
            );
            (art.path, art.identity)
        }
        _ => die("use --binary with --identity, or omit both to compile"),
    }
}

fn main() {
    let args = parse_args();
    let (binary, identity) = resolve_artifact(&args);
    let Some(corpus) = args.corpus else {
        if args.compile_out.is_some() {
            return;
        }
        die("--corpus DIR is required unless --compile-out is used alone");
    };

    let mut oracle = DumpOracle::new(&binary, identity.build_id)
        .unwrap_or_else(|e| die(&format!("oracle: {e:#}")));

    let files = list_corpus(&corpus);
    if let Some(expected) = args.expected_files
        && files.len() != expected
    {
        die(&format!(
            "expected {expected} corpus files, found {}",
            files.len()
        ));
    }

    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut replayed = 0usize;
    for path in &files {
        let bytes =
            fs::read(path).unwrap_or_else(|e| die(&format!("read {}: {e}", path.display())));
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

    if let Some(expected) = args.expected_files
        && replayed != expected
    {
        die(&format!("replayed {replayed} != expected-files {expected}"));
    }

    let report = oracle.report(admitted, rejected, replayed);
    let hash = identity.artifact_hash.clone().unwrap_or_default();
    println!(
        "ORACLE_RESULT target={} replayed={} admitted={} rejected={} edges={} digest={} canonical_build={} artifact_hash={}",
        identity.target_id,
        report.replayed,
        report.admitted,
        report.rejected,
        report.edge_count,
        report.digest.to_hex(),
        identity.build_id.to_hex(),
        hash
    );

    if let Some(out) = args.out {
        if let Some(parent) = out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let body = serde_json::json!({
            "target": identity.target_id,
            "replayed": report.replayed,
            "admitted": report.admitted,
            "rejected": report.rejected,
            "edges": report.edge_count,
            "digest": report.digest.to_hex(),
            "canonical_build": identity.build_id.to_hex(),
            "artifact_hash": identity.artifact_hash,
            "binary": binary,
        });
        fs::write(&out, format!("{body}\n"))
            .unwrap_or_else(|e| die(&format!("write {}: {e}", out.display())));
    }
}
