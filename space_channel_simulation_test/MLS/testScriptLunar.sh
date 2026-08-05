#!/usr/bin/env bash
# Sweeps commit interval over {1,3,5,10}s under a fixed blackout window, on
# the LEO channel, to check the transcript mechanism's behaviour as the
# number of missed commits per blackout grows the same variable the base
# paper varies in Table 2 (missed commit count), but here under real
# tc netem emulation with the actual reconnect handshake, not an isolated
# single-machine benchmark.
#
# Run from repo root: bash test_commit_interval_sweep.sh [channel]
# channel defaults to leo.
set -euo pipefail
cd "$(dirname "$0")"

CHANNEL="lunar"
COMMIT_INTERVALS=(1 3 5 10)
BLACKOUT_ON=15
BLACKOUT_OFF=10
# ~2.56s RTT: recovery is a few seconds, so the LEO-scale 90s per-cycle
# window still fits multiple blackout cycles comfortably.
DURATION=120
# Lunar: 1282ms delay each way => ~2.56s RTT. report_timeout of 30s gives
# ~10 round trips of headroom, ample for one recovery plus 0.1% loss retries.
REPORT_TIMEOUT=30
TRANSCRIPT_MAX_BYTES=20000

echo "=== 0. Sanity check the datagram preamble mechanism is present ==="
grep -q "PreambleSocket" testbed-runner/src/main.rs \
    || { echo "FIX NOT PRESENT in this checkout -- stop here."; exit 1; }

echo
echo "=== 1. Build once ==="
cargo build --release 2>&1 | tail -30

RESULTS_DIR="../../results/sweep-results-lunar/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"
echo ""
echo ">>> RESULTS_DIR = $RESULTS_DIR   <<<  (relative to repo root, NOT /tmp)"
echo ">>>   tail -f $RESULTS_DIR/bob_i1.log"
echo ""
SUMMARY="$RESULTS_DIR/summary.tsv"
printf "interval_s\tmissed_commits_est\tembedded_bytes\ttranscript_truncated\treconnect_epoch_matched\trecovery_flush_bytes\tverdict\n" > "$SUMMARY"

echo
echo "=== 2. Namespaces + veth (recreated once, reused across the sweep) ==="
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

echo
echo "=== 3. Apply channel: $CHANNEL ==="
sudo ./apply_channel.sh "$CHANNEL" ns-alice veth-a
sudo ./apply_channel.sh "$CHANNEL" ns-bob   veth-b

for INTERVAL in "${COMMIT_INTERVALS[@]}"; do
    echo
    echo "############################################################"
    echo "### commit-interval-secs = $INTERVAL   (channel=$CHANNEL)"
    echo "############################################################"

    BOOTSTRAP=$(mktemp -d)
    ALICE_CSV="$RESULTS_DIR/alice_i${INTERVAL}.csv"
    BOB_CSV="$RESULTS_DIR/bob_i${INTERVAL}.csv"
    ALICE_LOG="$RESULTS_DIR/alice_i${INTERVAL}.log"
    BOB_LOG="$RESULTS_DIR/bob_i${INTERVAL}.log"

    sudo pkill -9 -f "testbed-runner" 2>/dev/null || true
    sleep 1

    # Hard ceiling on this iteration generous margin over duration so a
    # normal run never trips it, but nothing can silently hang undetected.
    HARD_TIMEOUT=$(( DURATION + BLACKOUT_ON + BLACKOUT_OFF + REPORT_TIMEOUT + 60 ))

    BOB_CMD=(sudo timeout --foreground "${HARD_TIMEOUT}s"
        ip netns exec ns-bob env RUST_LOG=info,quic_mls=debug,testbed_runner=debug
        ../../target/release/testbed-runner
        --role bob --bind 10.200.1.2:5000
        --bootstrap-dir "$BOOTSTRAP"
        --commit-interval-secs "$INTERVAL" --duration-secs "$DURATION"
        --blackout-on-secs "$BLACKOUT_ON" --blackout-off-secs "$BLACKOUT_OFF"
        --report-timeout-secs "$REPORT_TIMEOUT"
        --out "$BOB_CSV")
    echo "BOB CMD: ${BOB_CMD[*]}"
    "${BOB_CMD[@]}" > "$BOB_LOG" 2>&1 &
    BOB_PID=$!
    sleep 1

    ALICE_CMD=(sudo timeout --foreground "${HARD_TIMEOUT}s"
        ip netns exec ns-alice env RUST_LOG=info,quic_mls=debug,testbed_runner=debug
        ../../target/release/testbed-runner
        --role alice --bind 10.200.1.1:5001 --peer 10.200.1.2:5000
        --bootstrap-dir "$BOOTSTRAP"
        --commit-interval-secs "$INTERVAL" --duration-secs "$DURATION"
        --blackout-on-secs "$BLACKOUT_ON" --blackout-off-secs "$BLACKOUT_OFF"
        --report-timeout-secs "$REPORT_TIMEOUT"
        --transcript-max-bytes "$TRANSCRIPT_MAX_BYTES"
        --out "$ALICE_CSV")
    echo "ALICE CMD: ${ALICE_CMD[*]}"
    "${ALICE_CMD[@]}" > "$ALICE_LOG" 2>&1 || true

    wait "$BOB_PID" 2>/dev/null || true

    # --- extract signal ---
    missed_est=$(( BLACKOUT_ON / INTERVAL ))
    embedded_bytes=$(grep "handshake_transcript_embedded" "$ALICE_CSV" 2>/dev/null | tail -1 | cut -d, -f3 || echo "")
    [ -z "$embedded_bytes" ] && embedded_bytes="NONE"

    # Truncated if the encoded size is suspiciously capped near the byte budget
    truncated="no"
    if [ "$embedded_bytes" != "NONE" ] && [ "$embedded_bytes" -ge $((TRANSCRIPT_MAX_BYTES - 50)) ]; then
        truncated="LIKELY"
    fi

    epoch_matched="no"
    if grep -qi "reconnect_handshake_0rtt_accepted\|blackout_recovery_flush" "$ALICE_CSV" 2>/dev/null; then
        epoch_matched="yes"
    fi
    if grep -qiE "decrypt.*fail|aead.*fail|reset|CRYPTO_BUFFER_EXCEEDED" "$BOB_LOG" "$ALICE_LOG" 2>/dev/null; then
        epoch_matched="no (error seen)"
    fi

    flush_bytes=$(grep "blackout_recovery_flush" "$ALICE_CSV" 2>/dev/null | tail -1 | cut -d, -f3 || echo "")
    [ -z "$flush_bytes" ] && flush_bytes="NONE"

    verdict="OK"
    if [ "$epoch_matched" != "yes" ] || [ "$flush_bytes" = "NONE" ]; then
        verdict="LIVELOCK-SUSPECT"
    fi
    if [ "$truncated" = "LIKELY" ] && [ "$verdict" = "LIVELOCK-SUSPECT" ]; then
        verdict="LIVELOCK-CONFIRMED (transcript truncated)"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$INTERVAL" "$missed_est" "$embedded_bytes" "$truncated" "$epoch_matched" "$flush_bytes" "$verdict" \
        >> "$SUMMARY"

    echo "--- interval=${INTERVAL}s result: verdict=$verdict, embedded_bytes=$embedded_bytes, flush_bytes=$flush_bytes ---"
    rm -rf "$BOOTSTRAP"
done

echo
echo "=== 4. Cleanup channel ==="
sudo ./apply_channel.sh clear ns-alice veth-a
sudo ./apply_channel.sh clear ns-bob   veth-b

echo
echo "=== SUMMARY (channel=$CHANNEL, blackout_on=${BLACKOUT_ON}s, transcript_max_bytes=${TRANSCRIPT_MAX_BYTES}) ==="
column -t -s $'\t' "$SUMMARY"
