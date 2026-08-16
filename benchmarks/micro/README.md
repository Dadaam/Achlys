# Micro-targets

These are **mechanism** tests, not superiority or performance claims
(Master Plan §20.1 / §24.6). A synthetic crash, rejected checksum, or
observed timeout proves that the corresponding execution path works. It
does **not** show that Achlys is faster or more effective than AFL++,
LibAFL, or any other fuzzer.

Each file exports one harness:

```c
int achlys_micro_<name>(const uint8_t *data, size_t len);
```

| File | Function | Mechanism | Trigger |
| --- | --- | --- | --- |
| `crash_if_magic.c` | `achlys_micro_crash_if_magic` | crash / magic comparison | input starts with `BUG!` |
| `magic_u32.c` | `achlys_micro_magic_u32` | crash / magic `u32` | first 4 bytes are `0xDEADBEEF` little-endian (`ef be ad de`) |
| `checksum.c` | `achlys_micro_checksum` | checksum then crash | `data[0] == xor(data[1..len-1])` (remainder) and `data[1] == 0x41` |
| `timeout_hang.c` | `achlys_micro_timeout_hang` | timeout / hang | input starts with `HANG` (`while (1) {}`) |

Invalid checksums return `0` without crashing. `crash_if_magic.c` also
keeps `parse` / `LLVMFuzzerTestOneInput` for existing compile tests.

Run the deterministic harness:

```bash
cargo test -p achlys-bridge --all-targets
```
