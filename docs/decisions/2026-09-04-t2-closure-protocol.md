# T2 closure protocol

Status: implementation paused by the owner; planning revision only; not an
acceptance record.

The later 2026-09-04 instruction requests only a detailed plan. The
[updated roadmap](../plans/2026-09-04-t2-and-research-roadmap.md) is the operational
specification: it records completed local changes, unvalidated drafts,
observations, hypotheses, alternatives and remaining evidence. It supersedes
ambiguous or underspecified points in this initial closure protocol. No final
ladder or live-restart acceptance is claimed.

The owner authorized autonomous completion of T2 on 2026-09-04, including
plan adjustments and atomic commits. T3 remains outside this change.

## Required changes

1. Preserve LibAFL restart state and the original worker deadline; exercise
   real process death, not only offline continuation.
2. Make candidate publication/recovery atomic and journal recovery tolerate
   an interrupted final append without hiding corruption in committed records.
3. Publish local discoveries directly, preserve their origin, and avoid
   periodic full-directory scans during fuzzing.
4. Bound pending transport work and make overload explicit. Preserve canonical
   corpus objects and recovery information.
5. Keep the canonical and sanitizer input contracts consistent and enforce
   execution deadlines during input delivery as well as target execution.
6. Verify canonical reconstruction, worker continuation and crash artifacts.

## Validation and acceptance

- Format, Clippy, workspace tests and H0/T1/T2 integration smoke must pass on
  the final implementation commit.
- Run the Linux 1/2/4/8 ladder (up to available CPUs), five 300-second trials
  per cell. Record affinity, CPU quota, machine details, source SHA, command,
  exit status, raw counts and elapsed time; retain every failed cell.
- Compare against independent H0 workers on the same host and with the same
  resource limit, input corpus and execution contract. Report throughput
  overhead separately from coverage; the H0 overhead budget remains 5%.
- Host saturation is assessed using the independent workers, not an assumed
  linear speedup. A virtual/shared host is development evidence only.
- Preserve raw evidence and a reproducible analysis script. An acceptance
  record must state actual results and limitations, never infer success from
  the presence of code or from historical measurements.

`--join` remains offline continuation, as specified by the original T2
decision. A newly added worker must load the accepted corpus on continuation.
Live attachment to a running broker and heterogeneous selective diffusion
remain future work. T2 uses LLMP for live homogeneous sharing and the canonical
authority for published measurement and durable accepted snapshots.

## Release scope

The first usable research release need not wait for adaptive allocation,
concolic execution or ML. Their research gates remain intact and optional;
none is implemented or claimed by this T2 closure.
