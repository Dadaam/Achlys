use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use achlys_bridge::{AutoCompiler, ForkExecTarget};
use achlys_core::{CortexInterface, FuzzerBuilder, FuzzerConfig};
use achlys_cortex::{AutoTrainer, CortexModel, HotSwapCortex};

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

        /// ONNX model path for AI-guided mutations (Stage 2).
        /// If not provided, the model is trained autonomously during fuzzing.
        #[arg(short, long)]
        model: Option<PathBuf>,

        /// Disable autonomous AI training (havoc-only mode)
        #[arg(long)]
        no_ai: bool,

        /// C/C++ source files to compile with SanCov instrumentation (graybox mode)
        #[arg(short, long, num_args = 1..)]
        source: Vec<PathBuf>,

        /// Plateau timeout in seconds before escalating strategy
        #[arg(long, default_value = "600")]
        plateau_timeout: u64,

        /// Maximum input size in bytes
        #[arg(long, default_value = "4096")]
        max_input_len: usize,

        /// Delay in seconds before first autonomous training (default: 300s = 5min)
        #[arg(long, default_value = "300")]
        train_delay: u64,
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
            no_ai,
            source,
            plateau_timeout,
            max_input_len,
            train_delay,
        } => {
            let config = FuzzerConfig {
                corpus_dir: corpus.clone(),
                crashes_dir: output,
                initial_inputs: 8,
                max_input_len,
                plateau_timeout: Duration::from_secs(plateau_timeout),
                model_path: model.clone(),
            };

            let cortex = setup_cortex(
                no_ai,
                model.as_ref(),
                max_input_len,
                corpus.as_ref(),
                train_delay,
                plateau_timeout,
            )?;

            let builder = FuzzerBuilder::new().config(config).cortex(cortex);

            if !source.is_empty() {
                println!("[achlys] compiling source files with SanCov instrumentation...");
                let compiler = AutoCompiler::new(std::env::temp_dir().join("achlys_build"));
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

/// Set up the AI cortex based on CLI flags.
///
/// Returns `None` for `--no-ai`, a loaded `CortexModel` for `--model`,
/// or a `HotSwapCortex` with autonomous training for the default mode.
fn setup_cortex(
    no_ai: bool,
    model: Option<&PathBuf>,
    max_input_len: usize,
    corpus: Option<&PathBuf>,
    train_delay: u64,
    plateau_timeout: u64,
) -> Result<Option<Arc<dyn CortexInterface>>> {
    if no_ai {
        println!("[achlys] AI disabled (--no-ai)");
        return Ok(None);
    }

    if let Some(model_path) = model {
        let cortex_model = CortexModel::load(model_path, max_input_len)
            .context("failed to load ONNX model")?;
        return Ok(Some(Arc::new(cortex_model)));
    }

    // Autonomous mode: HotSwapCortex starts empty, AutoTrainer fills it
    let hotswap = HotSwapCortex::empty(max_input_len);

    // Determine corpus dir for training
    let train_corpus = corpus
        .cloned()
        .unwrap_or_else(|| PathBuf::from("./runtime/corpus"));

    let model_output = std::env::temp_dir()
        .join("achlys_models")
        .join("auto_brain.onnx");

    let training_script = find_training_script()?;

    let mut trainer = AutoTrainer::new(&train_corpus, &model_output, max_input_len)
        .with_initial_delay(Duration::from_secs(train_delay))
        .with_retrain_interval(Duration::from_secs(plateau_timeout * 2))
        .with_epochs(30)
        .with_min_corpus_size(20)
        .with_training_script(&training_script);

    let hotswap_for_thread = hotswap.clone();
    let model_ready = trainer.model_ready_flag();

    // Spawn monitoring thread for autonomous training
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(10));

            if let Err(e) = trainer.tick() {
                eprintln!("[achlys-trainer] error: {}", e);
            }

            // Hot-load new model when ready
            if model_ready.load(std::sync::atomic::Ordering::Acquire) {
                if let Err(e) = hotswap_for_thread.load_model(&model_output) {
                    eprintln!("[achlys-trainer] failed to hot-load model: {}", e);
                }
                trainer.acknowledge_model();
            }
        }
    });

    println!(
        "[achlys] autonomous training enabled (delay: {}s, corpus: {})",
        train_delay,
        train_corpus.display()
    );

    Ok(Some(hotswap as Arc<dyn CortexInterface>))
}

/// Find the training script relative to the binary or in known locations.
fn find_training_script() -> Result<PathBuf> {
    // Try relative to current dir
    let candidates = [
        PathBuf::from("src/cortex/training/train.py"),
        PathBuf::from("cortex/training/train.py"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    // Try relative to the executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let script = dir.join("../src/cortex/training/train.py");
        if script.exists() {
            return Ok(script);
        }
    }

    anyhow::bail!(
        "training script not found. Expected at: src/cortex/training/train.py\n\
         Run from the project root or provide --model with a pre-trained ONNX model."
    )
}
