#!/usr/bin/env bash
# Mars-channel smoke test for the datagram preamble reconnection mechanism.
#
# Real profile, taken directly from apply_channel.sh (not guessed):
#   delay=240000ms each direction, jitter=0ms, loss=1%, rate=500kbit
# -> a full round trip is ~480s (8 minutes) with zero jitter, so the
# specific reordering risk flagged in review (Finding 2) has far less room
# to manifest here than on LEO -- there is no per-packet delay variance to
# cause reordering. Loss-driven retransmission could still reorder things,
# but that is a narrower, weaker version of the same risk, not the same one.
#
# WALL-CLOCK COST: this is NOT a quick test. A single reconnect attempt
# takes ~8 minutes minimum even with zero loss; with 1% loss and PTO-driven
# retransmission that can stretch to 15-20 minutes for one cycle. Defaults
# below run ONLY interval=1, ONE cycle, as a first correctness check --
# expect this single run to take at least 25-30 minutes wall-clock. Do not
# default to the full {1,3,5,10} sweep here; each interval added multiplies
# the wall-clock cost by roughly the same amount.
#
# Run from repo root: bash testScriptMars.sh
set -euo pipefail
cd "$(dirname "$0")"

CHANNEL="mars"
# Only interval=1 by default -- see wall-clock warning above. Widen this
# array (e.g. to (1 3)) only once a single interval=1 run has passed cleanly
# and you've budgeted the extra wall-clock time deliberately.
COMMIT_INTERVALS=(1 3 5 10)

# Kept deliberately small and unchanged from the LEO test: this checks
# whether the mechanism recovers correctly under Mars's actual per-packet
# characteristics (delay, loss, rate), not whether it can survive a
# Mars-scale, hours-long blackout -- that is a separate, much larger backlog
# question already covered by the transcript-max-bytes analysis. Producing
# and applying 10 missed commits under real 240s delay is the meaningful
# test here; a longer blackout only adds wall-clock time without adding
# new information about the mechanism itself.
BLACKOUT_ON=15
BLACKOUT_OFF=10

# A full round trip is ~480s. report-timeout must comfortably exceed that
# PLUS room for at least one PTO-driven retransmission under 1% loss, or
# every single attempt will be falsely reported as a failure regardless of
# whether the mechanism actually works. 900s (15 min) gives ~2 round trips
# of headroom before giving up on one cycle.
REPORT_TIMEOUT=900

# Traced directly from a real run: at DURATION=1500, Bob's own scenario
# clock ran out and his process exited ~4.5 minutes BEFORE Alice's
# wait_for_ready even finished resolving -- by the time Alice tried to
# reconnect, nobody was listening. The real critical path is: local
# blackout_off (10s) + close-notification propagation (~240s) + Bob writing
# the next cycle marker + Alice's wait_for_ready resolving + the actual
# reconnect round trip (480s+, more under 1% loss retransmission). 3600s
# gives comfortable margin for one full cycle including a retry, on both
# Bob's and Alice's side (they share this value).
DURATION=3600

TRANSCRIPT_MAX_BYTES=20000

echo "=== 0. Sanity check the datagram preamble mechanism is present ==="
grep -q "PreambleSocket" testbed-runner/src/main.rs \
    || { echo "FIX NOT PRESENT in this checkout -- stop here."; exit 1; }

echo
echo "=== 1. Build once ==="
cargo build --release 2>&1 | tail -30

RESULTS_DIR="./sweep-results-mars/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"
echo ""
echo ">>> RESULTS_DIR = $RESULTS_DIR   <<<  (relative to repo root, NOT /tmp)"
echo ">>> This run is on the Mars channel: ~8min RTT, expect ~25-30 min wall-clock."
echo ">>>   tail -f $RESULTS_DIR/bob_i1.log   (in another terminal, to watch progress)"
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

    # Hard ceiling on this iteration -- generous margin over duration so a
    # normal run never trips it, but nothing can silently hang undetected.
    HARD_TIMEOUT=$(( DURATION + BLACKOUT_ON + BLACKOUT_OFF + REPORT_TIMEOUT + 60 ))

    BOB_CMD=(sudo timeout --foreground "${HARD_TIMEOUT}s"
        ip netns exec ns-bob env RUST_LOG=info,quic_mls=debug,testbed_runner=debug
        ./target/release/testbed-runner
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
        ./target/release/testbed-runner
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
