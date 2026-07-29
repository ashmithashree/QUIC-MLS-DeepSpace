#!/usr/bin/env bash
# run_baseline.sh — run the QUIC + TLS 1.3 baseline across the four emulated channels.
#
# Assumes the same testbed you use for the QUIC-MLS runs:
#   * network namespaces ns-alice / ns-bob joined by a veth pair (veth-a / veth-b)
#   * server (ns-bob) at 10.0.0.2, client (ns-alice) at 10.0.0.1
#   * tc netem applied to veth-b (the bob-side egress) to shape the link
#
# It does NOT create the namespaces — your existing setup script does that. It only
# (re)applies the per-channel netem profile, runs the client against a fresh server,
# and writes JSONL to results/tls_baseline_<channel>.jsonl.
#
# IMPORTANT: the DELAY / LOSS numbers below are placeholders. Set them to the SAME
# values you used for the QUIC-MLS runs so the two protocols are compared on identical
# links. Consistency with your MLS profiles matters more than any nominal figure here.

set -euo pipefail

BIN="./target/release/tls-baseline"
SERVER_NS="ns-bob"
CLIENT_NS="ns-alice"
SERVER_IP="10.0.0.2"
SERVER_PORT="4443"
SHAPE_IF="veth-b"          # interface to apply netem on (bob-side)
RECONNECTS="${RECONNECTS:-16}"
OUTDIR="results"

mkdir -p "$OUTDIR"

# channel  ->  "netem-delay  netem-loss  blackout_ms  rtt_ms_tag"
# TODO: replace with the exact profiles from your MLS runs.
#   netem-delay is one-way; RTT is ~2x that on a symmetric veth pair.
#   rtt_ms_tag is a label only (echoed into each record).
declare -A PROFILES=(
  [LEO]="12ms        0.1%   0       25"
  [GEO]="130ms       0.5%   0       260"
  [Lunar]="1300ms    1%     15000   2600"
  [Mars]="360000ms   2%     60000   720000"
)

apply_netem() {
  local delay="$1" loss="$2"
  ip netns exec "$SERVER_NS" tc qdisc replace dev "$SHAPE_IF" root netem \
    delay "$delay" loss "$loss"
}

clear_netem() {
  ip netns exec "$SERVER_NS" tc qdisc del dev "$SHAPE_IF" root 2>/dev/null || true
}

run_channel() {
  local ch="$1"; read -r delay loss blackout rtt_tag <<<"${PROFILES[$ch]}"
  echo "== $ch : delay=$delay loss=$loss blackout=${blackout}ms rtt_tag=${rtt_tag}ms =="

  apply_netem "$delay" "$loss"

  # start server in the background inside ns-bob
  ip netns exec "$SERVER_NS" "$BIN" server --listen "${SERVER_IP}:${SERVER_PORT}" &
  local srv_pid=$!
  sleep 1  # let it bind

  # run client inside ns-alice, capture JSONL
  #   --no-resumption is deliberately RUN TWICE below: once with 0-RTT allowed,
  #   once forced full-handshake, so Ch6 can show both. Comment out the pass you
  #   don't want.
  ip netns exec "$CLIENT_NS" "$BIN" client \
    --server "${SERVER_IP}:${SERVER_PORT}" \
    --channel "$ch" --rtt-ms "$rtt_tag" \
    --reconnects "$RECONNECTS" --blackout-ms "$blackout" \
    > "${OUTDIR}/tls_baseline_${ch}.jsonl"

  # forced full-handshake pass (ticket-expiry / long-blackout case)
  ip netns exec "$CLIENT_NS" "$BIN" client \
    --server "${SERVER_IP}:${SERVER_PORT}" \
    --channel "$ch" --rtt-ms "$rtt_tag" \
    --reconnects "$RECONNECTS" --blackout-ms "$blackout" --no-resumption \
    > "${OUTDIR}/tls_baseline_${ch}_noresume.jsonl"

  kill "$srv_pid" 2>/dev/null || true
  wait "$srv_pid" 2>/dev/null || true
  clear_netem
  echo "   -> ${OUTDIR}/tls_baseline_${ch}.jsonl (+ _noresume)"
}

cargo build --release --manifest-path Cargo.toml

for ch in LEO GEO Lunar Mars; do
  run_channel "$ch"
done

echo "Done. JSONL results in ${OUTDIR}/"
