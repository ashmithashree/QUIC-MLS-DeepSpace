#!/usr/bin/bash

set -euo pipefail
cd "$(dirname "$0")"

CHANNEL="${1:-leo}"
BIN="./target/release/tls-baseline"

# Per-channel reconnect count. Mars/Lunar are deliberately small: on the baseline
# EVERY reconnect is a real handshake at the channel RTT, so a few give a clean mean
# without an overnight wait.
case "$CHANNEL" in
  leo|geo)   RECONNECTS="${RECONNECTS:-16}" ;;
  lunar)     RECONNECTS="${RECONNECTS:-6}"  ;;
  mars)      RECONNECTS="${RECONNECTS:-3}"  ;;
  *) echo "unknown channel: $CHANNEL (use leo|geo|lunar|mars)"; exit 1 ;;
esac
BLACKOUT_MS="${BLACKOUT_MS:-0}"   # short offline gap between reconnects; 0 = back-to-back

# rtt tag (one-way delay in ms, matching apply_channel.sh) — label only, echoed to output
declare -A RTT_TAG=( [leo]=16 [geo]=250 [lunar]=1282 [mars]=240000 )

RESULTS_DIR="./tls-baseline-results/$(date +%Y%m%d-%H%M%S)-${CHANNEL}"
mkdir -p "$RESULTS_DIR"
echo ">>> RESULTS_DIR = $RESULTS_DIR"

echo "=== 1. Build ==="
cargo build --release 2>&1 | tail -20
test -x "$BIN" || { echo "binary not found at $BIN"; exit 1; }

echo "=== 2. Namespaces + veth ==="
sudo ip netns del ns-alice 2>/dev/null || true
sudo ip netns del ns-bob   2>/dev/null || true
sudo ip netns add ns-alice
sudo ip netns add ns-bob
sudo ip link add veth-a type veth peer name veth-b
sudo ip link set veth-a netns ns-alice
sudo ip link set veth-b netns ns-bob
sudo ip netns exec ns-alice ip addr add 10.200.1.1/24 dev veth-a
sudo ip netns exec ns-bob   ip addr add 10.200.1.2/24 dev veth-b
sudo ip netns exec ns-alice ip link set veth-a up
sudo ip netns exec ns-bob   ip link set veth-b up
sudo ip netns exec ns-alice ip link set lo up
sudo ip netns exec ns-bob   ip link set lo up
sudo ip netns exec ns-alice ethtool -K veth-a tx off rx off
sudo ip netns exec ns-bob   ethtool -K veth-b tx off rx off
sudo ip netns exec ns-alice ping -c 2 10.200.1.2

echo "=== 3. Apply channel: $CHANNEL (both ends) ==="
sudo ./apply_channel.sh "$CHANNEL" ns-alice veth-a
sudo ./apply_channel.sh "$CHANNEL" ns-bob   veth-b

run_pass() {
  local pass="$1"; shift            # "resume" | "noresume"
  local extra=("$@")                # extra client flags
  echo "--- pass: $pass (reconnects=$RECONNECTS) ---"
  sudo pkill -9 -f "tls-baseline" 2>/dev/null || true
  sleep 1

  sudo ip netns exec ns-bob "$BIN" server --listen 10.200.1.2:4443 \
      > "$RESULTS_DIR/server_${pass}.log" 2>&1 &
  local srv=$!
  sleep 1

  sudo ip netns exec ns-alice "$BIN" client \
      --server 10.200.1.2:4443 --bind 10.200.1.1:0 \
      --channel "$CHANNEL" --rtt-ms "${RTT_TAG[$CHANNEL]}" \
      --reconnects "$RECONNECTS" --blackout-ms "$BLACKOUT_MS" \
      "${extra[@]}" \
      > "$RESULTS_DIR/tls_baseline_${CHANNEL}_${pass}.jsonl" \
      2> "$RESULTS_DIR/client_${pass}.log" || true

  sudo kill "$srv" 2>/dev/null || true
  wait "$srv" 2>/dev/null || true
  echo "    -> $RESULTS_DIR/tls_baseline_${CHANNEL}_${pass}.jsonl"
}

echo "=== 4. Runs ==="
run_pass resume
run_pass noresume --no-resumption

echo "=== 5. Clear channel ==="
sudo ./apply_channel.sh clear ns-alice veth-a
sudo ./apply_channel.sh clear ns-bob   veth-b

echo
echo "=== DONE. JSONL in $RESULTS_DIR ==="
head -n 2 "$RESULTS_DIR"/tls_baseline_"${CHANNEL}"_resume.jsonl 2>/dev/null || true