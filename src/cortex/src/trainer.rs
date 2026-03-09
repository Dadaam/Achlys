use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Manages autonomous LSTM training during fuzzing.
///
/// When the fuzzer accumulates enough corpus samples, the AutoTrainer
/// spawns a background Python process that trains an ONNX model.
/// The model can then be hot-loaded into the CortexModel for AI mutations.
///
/// Training cycle:
/// 1. Fuzzer runs havoc → corpus grows
/// 2. Timer fires → AutoTrainer spawns `train.py`
/// 3. Training runs in background (fuzzing continues)
/// 4. Model ready → `model_ready` flag set
/// 5. Builder hot-loads the model → AI mutations activated
/// 6. After `retrain_interval` → repeat from step 2 with enriched corpus
pub struct AutoTrainer {
    corpus_dir: PathBuf,
    model_output: PathBuf,
    max_seq_len: usize,
    epochs: usize,
    /// Minimum corpus size before training is worthwhile.
    min_corpus_size: usize,
    /// How long to wait before first training attempt.
    initial_delay: Duration,
    /// How long between re-training cycles.
    retrain_interval: Duration,
    /// Flag set when a new model is ready for loading.
    model_ready: Arc<AtomicBool>,
    /// Path to the training script.
    training_script: PathBuf,
    /// Current training process, if running.
    child: Option<Child>,
    /// When training was last started.
    last_train_start: Option<Instant>,
    /// When the trainer was created.
    created_at: Instant,
    /// Whether we've done the initial training.
    initial_done: bool,
}

impl AutoTrainer {
    pub fn new(
        corpus_dir: impl Into<PathBuf>,
        model_output: impl Into<PathBuf>,
        max_seq_len: usize,
    ) -> Self {
        Self {
            corpus_dir: corpus_dir.into(),
            model_output: model_output.into(),
            max_seq_len,
            epochs: 30,
            min_corpus_size: 50,
            initial_delay: Duration::from_secs(300), // 5 minutes
            retrain_interval: Duration::from_secs(600), // 10 minutes
            model_ready: Arc::new(AtomicBool::new(false)),
            training_script: PathBuf::from("src/cortex/training/train.py"),
            child: None,
            last_train_start: None,
            created_at: Instant::now(),
            initial_done: false,
        }
    }

    #[must_use]
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    #[must_use]
    pub fn with_retrain_interval(mut self, interval: Duration) -> Self {
        self.retrain_interval = interval;
        self
    }

    #[must_use]
    pub fn with_epochs(mut self, epochs: usize) -> Self {
        self.epochs = epochs;
        self
    }

    #[must_use]
    pub fn with_min_corpus_size(mut self, size: usize) -> Self {
        self.min_corpus_size = size;
        self
    }

    #[must_use]
    pub fn with_training_script(mut self, path: impl Into<PathBuf>) -> Self {
        self.training_script = path.into();
        self
    }

    /// Shared flag that signals when a new model is ready.
    pub fn model_ready_flag(&self) -> Arc<AtomicBool> {
        self.model_ready.clone()
    }

    /// Path where the trained model will be written.
    pub fn model_output_path(&self) -> &Path {
        &self.model_output
    }

    /// Called periodically from the fuzz loop (or a monitoring thread).
    ///
    /// Checks if a running training process has finished, and if so, sets the
    /// `model_ready` flag. If no training is running, determines whether it is
    /// time to start a new training cycle based on elapsed time and corpus size.
    pub fn tick(&mut self) -> Result<()> {
        // Check if a running training process has finished
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
                    if status.success() && self.model_output.exists() {
                        println!(
                            "[achlys-trainer] training complete → {}",
                            self.model_output.display()
                        );
                        self.model_ready.store(true, Ordering::Release);
                    } else {
                        eprintln!(
                            "[achlys-trainer] training failed (exit: {})",
                            status
                        );
                    }
                }
                Ok(None) => {
                    // Still running
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("[achlys-trainer] error checking training process: {}", e);
                    self.child = None;
                }
            }
        }

        // Don't start a new training if one is running
        if self.child.is_some() {
            return Ok(());
        }

        // Check if it's time to train
        let should_train = if !self.initial_done {
            // First training: wait for initial_delay
            self.created_at.elapsed() >= self.initial_delay
        } else {
            // Re-training: wait for retrain_interval since last start
            self.last_train_start
                .map(|t| t.elapsed() >= self.retrain_interval)
                .unwrap_or(false)
        };

        if !should_train {
            return Ok(());
        }

        // Check corpus size
        let corpus_size = count_files(&self.corpus_dir);
        if corpus_size < self.min_corpus_size {
            return Ok(());
        }

        // Launch training
        self.launch_training()
    }

    /// Spawn the Python training script as a child process.
    ///
    /// Creates the output directory if needed, then launches `python3 train.py`
    /// with the current corpus directory, model output path, and hyperparameters.
    fn launch_training(&mut self) -> Result<()> {
        // Ensure output directory exists
        if let Some(parent) = self.model_output.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            eprintln!(
                "[achlys-trainer] failed to create output directory {}: {}",
                parent.display(),
                e
            );
        }

        println!(
            "[achlys-trainer] starting training (corpus: {}, epochs: {}, seq_len: {})",
            self.corpus_dir.display(),
            self.epochs,
            self.max_seq_len
        );

        let child = Command::new("python3")
            .arg(&self.training_script)
            .args(["--corpus", &self.corpus_dir.to_string_lossy()])
            .args(["--output", &self.model_output.to_string_lossy()])
            .args(["--max-seq-len", &self.max_seq_len.to_string()])
            .args(["--epochs", &self.epochs.to_string()])
            .args(["--batch-size", "16"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn training process (is python3 with torch installed?)")?;

        self.child = Some(child);
        self.last_train_start = Some(Instant::now());
        self.initial_done = true;

        // Reset the model_ready flag so consumers know to check again
        self.model_ready.store(false, Ordering::Release);

        Ok(())
    }

    /// Check if a model was previously trained and is available.
    pub fn has_model(&self) -> bool {
        self.model_output.exists()
    }

    /// Acknowledge that the model has been loaded (reset the flag).
    pub fn acknowledge_model(&self) {
        self.model_ready.store(false, Ordering::Release);
    }

    /// Kill the training process if running.
    pub fn stop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for AutoTrainer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn count_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| entries.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_trainer_creation() {
        let trainer = AutoTrainer::new("/tmp/corpus", "/tmp/model.onnx", 256);
        assert_eq!(trainer.max_seq_len, 256);
        assert!(!trainer.has_model());
        assert!(!trainer.model_ready.load(Ordering::Acquire));
    }

    #[test]
    fn test_trainer_doesnt_start_before_delay() {
        let mut trainer = AutoTrainer::new("/tmp/corpus", "/tmp/model.onnx", 256)
            .with_initial_delay(Duration::from_secs(9999));

        // Should not start training (delay not elapsed)
        trainer.tick().unwrap();
        assert!(trainer.child.is_none());
    }

    #[test]
    fn test_count_files_empty() {
        let dir = std::env::temp_dir().join("achlys_test_empty_dir");
        let _ = fs::create_dir_all(&dir);
        assert_eq!(count_files(&dir), 0);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_model_ready_flag() {
        let trainer = AutoTrainer::new("/tmp/corpus", "/tmp/model.onnx", 256);
        let flag = trainer.model_ready_flag();
        assert!(!flag.load(Ordering::Acquire));

        flag.store(true, Ordering::Release);
        assert!(flag.load(Ordering::Acquire));

        trainer.acknowledge_model();
        assert!(!flag.load(Ordering::Acquire));
    }
}
