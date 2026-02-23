use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use achlys_bridge::{AutoCompiler, ForkExecTarget};
use achlys_core::{CortexInterface, FuzzerBuilder, FuzzerConfig};
use achlys_cortex::CortexModel;

#[derive(Parser)]
#[command(name = "achlys", about = "4-stage adaptive fuzzer — hunt zero-days in any binary")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fuzz a target binary
    Fuzz {
        /// Path to the target binary
        binary: PathBuf,

        /// Arguments to pass to the binary. Use @@ for file-based input delivery.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Seed corpus directory
        #[arg(short, long)]
        corpus: Option<PathBuf>,

        /// Output directory for crashes
        #[arg(short, long, default_value = "./crashes")]
        output: PathBuf,

        /// ONNX model path for AI-guided mutations (Stage 2)
        #[arg(short, long)]
        model: Option<PathBuf>,

        /// C/C++ source files to compile with SanCov instrumentation (graybox mode)
        #[arg(short, long, num_args = 1..)]
        source: Vec<PathBuf>,

        /// Plateau timeout in seconds before escalating strategy
        #[arg(long, default_value = "600")]
        plateau_timeout: u64,

        /// Maximum input size in bytes
        #[arg(long, default_value = "4096")]
        max_input_len: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Fuzz {
            binary,
            args,
            corpus,
            output,
            model,
            source,
            plateau_timeout,
            max_input_len,
        } => {
            let config = FuzzerConfig {
                corpus_dir: corpus,
                crashes_dir: output,
                initial_inputs: 8,
                max_input_len,
                plateau_timeout: std::time::Duration::from_secs(plateau_timeout),
                model_path: model.clone(),
            };

            // Load AI cortex if --model is provided
            let cortex: Option<Arc<dyn CortexInterface>> = if let Some(ref model_path) = model {
                let cortex_model = CortexModel::load(model_path, max_input_len)
                    .context("failed to load ONNX model")?;
                Some(Arc::new(cortex_model))
            } else {
                None
            };

            let builder = FuzzerBuilder::new().config(config).cortex(cortex);

            if !source.is_empty() {
                println!("[achlys] compiling source files with SanCov instrumentation...");
                let compiler = AutoCompiler::new("/tmp/achlys_build");
                let instrumented = compiler
                    .compile_binary(&source, "target_instrumented")
                    .context("source compilation failed")?;

                println!("[achlys] fuzzing instrumented binary: {}", instrumented.display());
                let target = ForkExecTarget::new(instrumented, args);
                builder.run(target)
            } else {
                println!("[achlys] fuzzing binary: {}", binary.display());
                let target = ForkExecTarget::new(binary, args);
                builder.run(target)
            }
        }
    }
}
