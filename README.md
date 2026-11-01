# CyberSec Subnet Allocator

A dependency-free Python tool for **safe, deterministic IPv4 subnet allocation**
inside a fixed address pool. Designed for cybersecurity / network-engineering
workflows where every allocation must be validated, non-overlapping, and auditable.

Built on the standard library (`ipaddress`, `copy`) — no third-party dependencies.

## Features

- **Host-to-prefix calculation** — recommends the smallest CIDR that fits N hosts
  (conventional `/30`–`/0` model; `/31` and `/32` are rejected by design).
- **Pool containment** — every subnet must sit inside an authorised IPv4 pool.
- **Conflict detection** — reports _all_ pairwise overlaps, not just the first.
- **Best-fit placement** — picks the smallest suitable free block (lowest address
  on ties) to minimise fragmentation.
- **Free-space accounting** — verifies allocated + free == pool size before
  returning `ACCEPTED`.
- **Fail-safe workflow** — the original configuration is deep-copied and never
  mutated; any validation failure returns `REJECTED` with the original preserved.
- **Automated test suite** — 16 self-contained tests covering happy paths and
  every failure mode (overlaps, IPv6, duplicates, malformed records, etc.).

## Status model

`plan_allocation()` returns a dict with one of:

| Status        | Meaning                                      |
| ------------- | -------------------------------------------- |
| `ACCEPTED`    | Candidate found, validated, config unchanged |
| `REJECTED`    | Bad input or rule violation                  |
| `NO CAPACITY` | Valid input, but no free block fits          |
