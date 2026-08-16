mod tui;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use achlys_bridge::ForkExecTarget;
use achlys_core::{CortexInterface, FuzzerBuilder, FuzzerConfig, shared_log_sink};
use achlys_cortex::CortexModel;

use crate::tui::{AchlysTui, create_tui_callback};

#[derive(Parser)]
#[command(name = "achlys", about = "LibAFL-based fuzzer")]
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

        /// ONNX model path for AI-guided mutations. Required to enable AI;
        /// auto-training is disabled.
        #[arg(short, long)]
        model: Option<PathBuf>,

        /// Force havoc-only mode (ignore --model)
        #[arg(long)]
        no_ai: bool,

        /// Disable TUI (use plain text output)
        #[arg(long)]
        no_tui: bool,

        /// Disabled: SanCov child coverage is not transported. Omit this flag.
        #[arg(short, long, num_args = 1..)]
        source: Vec<PathBuf>,

        /// Plateau timeout in seconds before escalating strategy
        #[arg(long, default_value = "600")]
        plateau_timeout: u64,

        /// Maximum input size in bytes
        #[arg(long, default_value = "4096")]
        max_input_len: usize,

        /// Autonomous training is disabled; this flag is ignored.
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
            no_tui,
            source,
            plateau_timeout,
            max_input_len,
            train_delay: _,
        } => {
            let config = FuzzerConfig {
                corpus_dir: corpus.clone(),
                crashes_dir: output,
                initial_inputs: 8,
                max_input_len,
                plateau_timeout: Duration::from_secs(plateau_timeout),
                model_path: model.clone(),
            };

            let cortex = setup_cortex(no_ai, model.as_ref(), max_input_len)?;

            let mode = if model.is_some() && !no_ai {
                "havoc → AI (model loaded)"
            } else {
                "havoc only"
            };

            let target_display = binary.display().to_string();

            let log_sink = shared_log_sink();
            let mut builder = FuzzerBuilder::new()
                .config(config)
                .cortex(cortex)
                .log_sink(log_sink.clone());

            // Set up TUI or plain text monitor
            let _tui_guard: Option<Arc<Mutex<AchlysTui>>> = if !no_tui {
                match AchlysTui::init(target_display.clone(), mode.to_string()) {
                    Ok((tui_instance, tui_state)) => {
                        let tui_arc = Arc::new(Mutex::new(tui_instance));
                        let callback = create_tui_callback(
                            tui_state.clone(),
                            tui_arc.clone(),
                            log_sink.clone(),
                        );
                        builder = builder.monitor(callback);
                        Some(tui_arc)
                    }
                    Err(e) => {
                        eprintln!("[achlys] TUI init failed ({}), falling back to text", e);
                        None
                    }
                }
            } else {
                None
            };

            if !source.is_empty() {
                anyhow::bail!(
                    "--source is disabled: SanCov child coverage is not transported, \
                     so this is not graybox. Omit --source."
                );
            }

            let target = ForkExecTarget::new(binary, args);
            builder.run(target)
        }
    }
}

/// Set up the AI cortex based on CLI flags.
///
/// AutoTrainer is not started: the live campaign corpus is in-memory and
/// is not connected to the training path.
fn setup_cortex(
    no_ai: bool,
    model: Option<&PathBuf>,
    max_input_len: usize,
) -> Result<Option<Arc<dyn CortexInterface>>> {
    if no_ai {
        return Ok(None);
    }

    let Some(model_path) = model else {
        return Ok(None);
    };

    let cortex_model =
        CortexModel::load(model_path, max_input_len).context("failed to load ONNX model")?;
    Ok(Some(Arc::new(cortex_model)))
}
