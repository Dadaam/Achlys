# Decision: T2 still lists the persist corpus at each sync

- Date: 2026-08-17
- Decision: keep path-indexed `scan_new_inputs` for T2. Do **not**
  accept T2 on this note. Do **not** start T3.
- Bound: replace the directory walk before T3 real corpora.

`7b2a40c` stopped re-reading file contents. Linux A/B on
`achlys-t2-linux` still listed 11–12 million paths in 120 s at 8
workers (`paths_listed`). That walk is O(corpus) and will not survive
T3-sized queues.

Required follow-up, not a T2 close:

- publish a candidate when LibAFL admits it locally (hook /
  decorated event manager);
- do not discover the worker's own writes by rescanning disk;
- keep a final sync only as a crash-recovery safety net.

Until that lands, `--sync-every` (default 256) is the load-bearing
mitigation. `--rescan` remains an A/B control only.

## 2026-09-04 planning update

Local commit `0688c60` replaces the periodic worker-corpus scan with publication
on local admission. This supersedes the implementation choice above on the
current local branch, but it has not passed live-restart, integration or final
performance validation. The spool quota implementation still scans pending
records; zero worker-corpus scans must not be described as zero filesystem work.
The [detailed T2-D plan](../plans/2026-09-04-t2-and-research-roadmap.md)
records provenance, metrics and load tests required before acceptance.
Implementation is paused at the owner's request.
