# QUIC-MLS: MLS-derived key agreement for QUIC over deep-space links

## What this project is
Replace QUIC's TLS 1.3 handshake with Messaging Layer Security (MLS) as the
underlying authenticated key exchange, so a QUIC connection can re-key and
reconnect from long-lived MLS group state instead of running a fresh
synchronous handshake. Target deployment: high-latency, intermittently
connected space links (LEO, GEO, Lunar relay, Mars relay).

This is "Architecture B" (full TLS replacement) from Dowling, Hale, Tian &
Wimalasiri, ePrint 2025/2063 / draft-tian-quic-quicmls. The construction is
adopted unmodified; the contribution of this project is the network-realistic
empirical evaluation that paper does not provide.

## Stack
- Language: Rust (edition 2021).
- QUIC transport: `quinn` / `quinn-proto`. Integration point is the
  `quinn::crypto::Session` trait, plus `crypto::ClientConfig` / `ServerConfig`.
- MLS: `mls-rs` (awslabs). Key hook is `Group::export_secret(label, context, len)`.
- Testbed (Linux only): network namespaces + veth pair + `tc netem`.
- Pin exact crate versions in Cargo.toml and record them in the README.
  Do not bump versions without asking first.

## How the binding works (read before touching crypto code)
- QUIC Initial keys stay standard: derived from the Destination Connection ID
  via the public salt in RFC 9001 §5.2. Do NOT source these from MLS.
- Handshake and 1-RTT keys come from MLS: feed `export_secret` output into
  QUIC's key schedule using QUIC's labels ("quic key", "quic iv", "quic hp")
  to build the `PacketKey` / `HeaderKey`.
- The MLS group is provisioned out-of-band. For the prototype, serialize the
  group state / Welcome message to a file and load it on both endpoints before
  connecting. There is no live Delivery Service.
- `read_handshake` / `write_handshake` should be trivial (at most a liveness
  confirmation); `is_handshaking` flips to false quickly.
- Re-key is driven by MLS Commits, NOT QUIC's native KEY_UPDATE. An applied
  Commit advances the epoch; `export_secret` then yields the next secret. Native
  KEY_UPDATE is disabled. Wire `next_1rtt_keys` to the next epoch's secret.
  This is the hardest part of the project — be careful about the ordering of
  "Commit applied -> epoch advances -> next secret available -> Quinn rotates",
  and test it in isolation before integrating.

## Build & test
- `cargo build`, `cargo test`.
- Run `cargo clippy -- -D warnings` and `cargo fmt` before any commit.
- Prefer `quinn-proto`'s deterministic, no-I/O state machine for unit-testing
  Session behaviour without real sockets.

## Current scope (target: 30 June 2026)
Phase 1 implementation plus testbed infrastructure. NOT the full experiment
matrix (that is Phase 3, July).

Definition of done:
1. A QUIC-MLS session exchanges encrypted application data using MLS-derived
   keys, with no TLS handshake on the wire.
2. Re-key on MLS Commit works mid-connection.
3. Reconnection after a dropped link re-derives keys from the current epoch with
   no fresh interactive handshake.
4. Telemetry emitted as CSV: time-to-first-secure-byte, reconnection latency,
   bytes-per-epoch, CPU-per-Commit.
5. A QUIC + TLS 1.3 baseline runs through the same testbed harness.

## Conventions
- No `unsafe` unless justified in a comment.
- MLS context labels must be identical on both endpoints; derivation has to be
  deterministic across peers.
- Errors: use `Result` with `thiserror`; no `unwrap()` outside tests.
- Comments explain the *why*. Name the subject explicitly; avoid vague "this"
  and "it".
