#!/usr/bin/env bash
cd "$(dirname "$0")"
while true; do
  clear
  echo "===== tls-baseline status @ $(date +%T) ====="
  if pgrep -f tls-baseline >/dev/null 2>&1; then
    echo "-- processes --"
    ps -eo etime,pid,cmd | grep '[t]ls-baseline' | sed 's/^/  /'
  else
    echo "-- no tls-baseline process running (run finished or not started) --"
  fi
  D=$(ls -dt tls-baseline-results/* 2>/dev/null | head -1)
  echo "-- results: ${D:-<none>} --"
  if [ -n "${D:-}" ]; then
    for f in "$D"/*.jsonl; do
      [ -e "$f" ] || continue
      echo "   $(basename "$f"): $(wc -l < "$f" 2>/dev/null) records"
    done
    last=$(cat "$D"/*.jsonl 2>/dev/null | tail -n1)
    [ -n "$last" ] && echo "   latest: $last"
  fi
  tx=$(sudo ip netns exec ns-alice ip -s link show veth-a 2>/dev/null | awk '/TX:/{getline; print $1}')
  echo "-- veth-a TX bytes: ${tx:-n/a}  (should keep climbing during a handshake) --"
  echo "(refreshes every 15s; Ctrl+C to stop watching — does NOT affect the run)"
  sleep 15
done
