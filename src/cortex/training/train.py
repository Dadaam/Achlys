#!/usr/bin/env python3
"""Train an LSTM/GRU model for Achlys AI-guided mutation (Stage 2).

The model learns byte-level patterns from a corpus of inputs that
triggered new coverage. At inference time, it predicts mutations
likely to discover additional coverage paths.

Architecture:
    Input: [batch_size, max_seq_len] float32 (bytes / 255.0)
    -> Linear embedding (1 -> hidden_size per position)
    -> LSTM/GRU (2 layers, bidirectional)
    -> Linear projection (hidden_size*2 -> 1 per position)
    -> Sigmoid -> [batch_size, max_seq_len] float32

Training objective:
    Next-byte prediction with teacher forcing. Given bytes[0..N-1],
    predict bytes[1..N]. MSE loss on normalized byte values.

Usage:
    python train.py --corpus runtime/corpus/json/ --output models/brain.onnx
    python train.py --corpus runtime/corpus/json/ --output models/brain.onnx --epochs 100 --hidden-size 256
"""

import argparse
import os
import sys

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader


class ByteCorpusDataset(Dataset):
    """Dataset of raw byte files from a corpus directory."""

    def __init__(self, corpus_dir: str, max_seq_len: int):
        self.max_seq_len = max_seq_len
        self.samples = []

        if not os.path.isdir(corpus_dir):
            print(f"[error] corpus directory not found: {corpus_dir}", file=sys.stderr)
            sys.exit(1)

        for name in sorted(os.listdir(corpus_dir)):
            path = os.path.join(corpus_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    data = f.read()
                if len(data) > 0:
                    self.samples.append(data)

        if len(self.samples) == 0:
            print(f"[error] no files found in corpus: {corpus_dir}", file=sys.stderr)
            sys.exit(1)

        print(f"[train] loaded {len(self.samples)} samples from {corpus_dir}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        data = self.samples[idx]
        # Normalize bytes to [0, 1] and pad/truncate to max_seq_len
        arr = np.frombuffer(data[: self.max_seq_len], dtype=np.uint8).astype(np.float32) / 255.0
        padded = np.zeros(self.max_seq_len, dtype=np.float32)
        padded[: len(arr)] = arr

        # Input: bytes[0..N-1], Target: bytes[1..N] (shifted by 1 for next-byte prediction)
        input_seq = padded.copy()
        target_seq = np.zeros_like(padded)
        target_seq[:-1] = padded[1:]
        target_seq[-1] = padded[-1]  # last byte predicts itself

        return torch.from_numpy(input_seq), torch.from_numpy(target_seq)


class ByteMutatorLSTM(nn.Module):
    """LSTM-based byte sequence mutator."""

    def __init__(self, max_seq_len: int, hidden_size: int = 128, num_layers: int = 2):
        super().__init__()
        self.max_seq_len = max_seq_len
        self.hidden_size = hidden_size

        # Per-position embedding: each byte value -> hidden_size features
        self.embed = nn.Linear(1, hidden_size)
        self.lstm = nn.LSTM(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=0.1 if num_layers > 1 else 0.0,
        )
        # Project back: hidden_size*2 (bidirectional) -> 1 per position
        self.project = nn.Linear(hidden_size * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [batch_size, max_seq_len]
        x = x.unsqueeze(-1)  # [batch_size, max_seq_len, 1]
        x = self.embed(x)  # [batch_size, max_seq_len, hidden_size]
        x, _ = self.lstm(x)  # [batch_size, max_seq_len, hidden_size*2]
        x = self.project(x)  # [batch_size, max_seq_len, 1]
        x = x.squeeze(-1)  # [batch_size, max_seq_len]
        x = self.sigmoid(x)  # clamp to [0, 1]
        return x


def train(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[train] device: {device}")

    dataset = ByteCorpusDataset(args.corpus, args.max_seq_len)
    loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=True, drop_last=True)

    model = ByteMutatorLSTM(
        max_seq_len=args.max_seq_len,
        hidden_size=args.hidden_size,
        num_layers=args.num_layers,
    ).to(device)

    print(f"[train] model params: {sum(p.numel() for p in model.parameters()):,}")

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.MSELoss()

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        batches = 0

        for input_seq, target_seq in loader:
            input_seq = input_seq.to(device)
            target_seq = target_seq.to(device)

            output = model(input_seq)
            loss = criterion(output, target_seq)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            batches += 1

        avg_loss = total_loss / max(batches, 1)
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"[train] epoch {epoch + 1}/{args.epochs} — loss: {avg_loss:.6f}")

    # Export to ONNX
    model.eval()
    model = model.cpu()
    dummy_input = torch.rand(1, args.max_seq_len)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    torch.onnx.export(
        model,
        dummy_input,
        args.output,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        opset_version=17,
    )

    print(f"[train] model exported: {args.output}")
    print(f"[train] input: [batch_size, {args.max_seq_len}] float32")
    print(f"[train] output: [batch_size, {args.max_seq_len}] float32")


def main():
    parser = argparse.ArgumentParser(
        description="Train LSTM byte mutator for Achlys Stage 2"
    )
    parser.add_argument(
        "--corpus", type=str, required=True,
        help="Directory containing corpus files (raw bytes)"
    )
    parser.add_argument(
        "--output", type=str, default="models/brain.onnx",
        help="Output path for the ONNX model"
    )
    parser.add_argument("--max-seq-len", type=int, default=256)
    parser.add_argument("--hidden-size", type=int, default=128)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--lr", type=float, default=0.001)

    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
