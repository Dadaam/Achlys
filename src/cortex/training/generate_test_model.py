#!/usr/bin/env python3
"""Generate a minimal ONNX test model for Achlys integration testing.

Creates a simple model that performs identity + small noise,
without requiring any training data. This validates the ONNX
inference pipeline end-to-end.

Output model:
  - Input: [batch_size, max_seq_len] float32
  - Output: [batch_size, max_seq_len] float32

Usage:
    python generate_test_model.py [--output models/test_brain.onnx] [--max-seq-len 256]
"""

import argparse
import os

import torch
import torch.nn as nn


class IdentityMutator(nn.Module):
    """Trivial model: returns input with learned small perturbations."""

    def __init__(self, max_seq_len: int):
        super().__init__()
        # Small linear perturbation layer
        self.perturb = nn.Linear(max_seq_len, max_seq_len, bias=True)
        # Initialize close to identity
        nn.init.eye_(self.perturb.weight)
        nn.init.uniform_(self.perturb.bias, -0.02, 0.02)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return torch.clamp(self.perturb(x), 0.0, 1.0)


def main():
    parser = argparse.ArgumentParser(description="Generate test ONNX model for Achlys")
    parser.add_argument(
        "--output", type=str, default="models/test_brain.onnx",
        help="Output path for the ONNX model"
    )
    parser.add_argument(
        "--max-seq-len", type=int, default=256,
        help="Maximum sequence length (must match Rust max_input_len)"
    )
    args = parser.parse_args()

    model = IdentityMutator(args.max_seq_len)
    model.eval()

    # Create dummy input for export
    batch_size = 1
    dummy_input = torch.rand(batch_size, args.max_seq_len)

    # Export to ONNX
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

    print(f"[achlys] test model saved: {args.output}")
    print(f"[achlys] input shape: [batch_size, {args.max_seq_len}] float32")
    print(f"[achlys] output shape: [batch_size, {args.max_seq_len}] float32")

    # Quick verification
    import onnxruntime as ort
    session = ort.InferenceSession(args.output)
    test_input = torch.rand(4, args.max_seq_len).numpy()
    result = session.run(None, {"input": test_input})
    print(f"[achlys] verification: input shape {test_input.shape} -> output shape {result[0].shape}")
    print("[achlys] test model OK")


if __name__ == "__main__":
    main()
