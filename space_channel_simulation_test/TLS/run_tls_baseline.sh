#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
CHANNEL="${1:-leo}"
BIN="./target/release/tls-baseline"
case "$CHANNEL" in
  leo|geo) RECONNECTS="${RECONNECTS:-16}"; IDLE=30 ;;
  lunar)   RECONNECTS="${RECONNECTS:-6}";  IDLE=60 ;;
  mars)    RECONNECTS="${RECONNECTS:-1}";  IDLE=3600 ;;
  *) echo "unknown channel: $CHANNEL (use leo|geo|lunar|mars)"; exit 1 ;;
esac
BLACKOUT_MS="${BLACKOUT_MS:-0}"
declare -A RTT_TAG=( [leo]=16 [geo]=250 [lunar]=1282 [mars]=240000 )
test -x "$BIN" || { echo "ERROR: $BIN not found. Build first WITHOUT sudo: cargo build --release --bin tls-baseline"; exit 1; }
RESULTS_DIR="./tls-baseline-results/$(date +%Y%m%d-%H%M%S)-${CHANNEL}"
mkdir -p "$RESULTS_DIR"
echo ">>> RESULTS_DIR = $RESULTS_DIR   (idle=${IDLE}s, reconnects=$RECONNECTS)"
echo "=== namespaces + veth ==="
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
echo "=== apply channel: $CHANNEL ==="
sudo ./apply_channel.sh "$CHANNEL" ns-alice veth-a
sudo ./apply_channel.sh "$CHANNEL" ns-bob   veth-b
run_pass() {
  local pass="$1"; shift; local extra=("$@")
  echo "--- pass: $pass (reconnects=$RECONNECTS, idle=${IDLE}s) ---"
  sudo pkill -9 -f "tls-baseline" 2>/dev/null || true; sleep 1
  sudo ip netns exec ns-bob "$BIN" server --listen 10.200.1.2:4443 --idle-timeout-secs "$IDLE" > "$RESULTS_DIR/server_${pass}.log" 2>&1 &
  local srv=$!; sleep 1
  sudo ip netns exec ns-alice "$BIN" client --server 10.200.1.2:4443 --bind 10.200.1.1:0 \
      --channel "$CHANNEL" --rtt-ms "${RTT_TAG[$CHANNEL]}" --reconnects "$RECONNECTS" --blackout-ms "$BLACKOUT_MS" \
      --idle-timeout-secs "$IDLE" "${extra[@]}" \
      > "$RESULTS_DIR/tls_baseline_${CHANNEL}_${pass}.jsonl" 2> "$RESULTS_DIR/client_${pass}.log" || true
  sudo kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true
  local n; n=$(wc -l < "$RESULTS_DIR/tls_baseline_${CHANNEL}_${pass}.jsonl" 2>/dev/null || echo 0)
  echo "    -> $RESULTS_DIR/tls_baseline_${CHANNEL}_${pass}.jsonl  ($n records)"
}
run_pass resume
run_pass noresume --no-resumption
sudo ./apply_channel.sh clear ns-alice veth-a
sudo ./apply_channel.sh clear ns-bob   veth-b
echo "=== DONE. JSONL in $RESULTS_DIR ==="
head -n 2 "$RESULTS_DIR"/tls_baseline_"${CHANNEL}"_resume.jsonl 2>/dev/null || echo "(resume file empty -- check client_resume.log)"
