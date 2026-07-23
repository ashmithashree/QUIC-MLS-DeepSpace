#!/usr/bin/env python3
import argparse
import csv
import statistics as stats
import sys
from collections import defaultdict


def load_rows(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for r in reader:
            if len(r) < 5:
                continue
            ts, event, epoch, nbytes, dur = r[0], r[1], r[2], r[3], r[4]
            rows.append({
                "ts": int(ts),
                "event": event,
                "epoch": int(epoch),
                "bytes": float(nbytes),
                "duration_ms": float(dur),
            })
    return rows


def compute_sb_commit(rows):
    """Pair commit_cpu + commit_net per epoch -> SB_commit per epoch (ms)."""
    by_epoch = defaultdict(dict)
    for r in rows:
        if r["event"] in ("commit_cpu", "commit_net"):
            by_epoch[r["epoch"]][r["event"]] = r["duration_ms"]

    sb_per_epoch = {}
    for epoch, d in by_epoch.items():
        if "commit_cpu" in d and "commit_net" in d:
            sb_per_epoch[epoch] = d["commit_cpu"] + d["commit_net"]
    return sb_per_epoch


def compute_recovery(rows):
    """Recovery cost per blackout event (ms), from external_commit_recovery."""
    values = [r["duration_ms"] for r in rows
              if r["event"] == "external_commit_recovery"]
    return values


def main():
    ap = argparse.ArgumentParser(description="Compute QUIC-MLS Security Budget from telemetry CSV")
    ap.add_argument("csv_path", help="Path to testbed-runner telemetry CSV")
    ap.add_argument("--channel", required=True, help="Channel label, e.g. LEO/GEO/Lunar/Mars")
    ap.add_argument("--interval-seconds", type=float, required=True,
                     help="MLS Commit interval used for this run (seconds)")
    ap.add_argument("--blackout-period-seconds", type=float, default=None,
                     help="Time between blackout starts (seconds). "
                          "If omitted, inferred from blackout_start timestamps in the CSV.")
    ap.add_argument("--mission-seconds", type=float, default=86400.0,
                     help="Mission window T over which to project SB_total (default 1 day)")
    ap.add_argument("--out-csv", default=None, help="Optional path to append a result row to")
    args = ap.parse_args()

    rows = load_rows(args.csv_path)
    if not rows:
        sys.exit(f"No rows parsed from {args.csv_path}")

    # Steady-state per-commit cost
    sb_per_epoch = compute_sb_commit(rows)
    if not sb_per_epoch:
        sys.exit("No paired commit_cpu/commit_net rows found — check event names.")
    sb_commit_mean = stats.mean(sb_per_epoch.values())
    sb_commit_stdev = stats.pstdev(sb_per_epoch.values()) if len(sb_per_epoch) > 1 else 0.0
    sb_rate = sb_commit_mean / args.interval_seconds  # ms per second of mission time

    # Recovery cost per blackout
    recovery_values = compute_recovery(rows)
    sb_recovery_mean = stats.mean(recovery_values) if recovery_values else 0.0

    # Blackout period: from args, or inferred from consecutive blackout_start timestamps
    blackout_period = args.blackout_period_seconds
    if blackout_period is None:
        starts = sorted(r["ts"] for r in rows if r["event"] == "blackout_start")
        if len(starts) >= 2:
            # timestamps assumed epoch-ms; convert gaps to seconds
            gaps = [(starts[i + 1] - starts[i]) / 1000.0 for i in range(len(starts) - 1)]
            blackout_period = stats.mean(gaps)
        else:
            blackout_period = float("inf")  # no repeated blackout observed in this run

    n_blackouts_in_mission = args.mission_seconds / blackout_period if blackout_period else 0

    sb_total = sb_rate * args.mission_seconds + sb_recovery_mean * n_blackouts_in_mission

    print(f"Channel:                 {args.channel}")
    print(f"Commit interval (s):     {args.interval_seconds}")
    print(f"Epochs observed:         {len(sb_per_epoch)}")
    print(f"SB_commit mean (ms):     {sb_commit_mean:.3f}  (stdev {sb_commit_stdev:.3f})")
    print(f"SB_rate (ms/s):          {sb_rate:.6f}")
    print(f"Blackouts w/ recovery:   {len(recovery_values)}")
    print(f"SB_recovery mean (ms):   {sb_recovery_mean:.3f}")
    print(f"Blackout period (s):     {blackout_period:.1f}" if blackout_period != float("inf") else "Blackout period (s):     n/a (single/no blackout in trace)")
    print(f"Mission window T (s):    {args.mission_seconds}")
    print(f"SB_total over T (ms):    {sb_total:.3f}")

    if args.out_csv:
        write_header = False
        try:
            with open(args.out_csv, "r"):
                pass
        except FileNotFoundError:
            write_header = True
        with open(args.out_csv, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["channel", "interval_s", "sb_commit_mean_ms", "sb_rate_ms_per_s",
                            "sb_recovery_mean_ms", "blackout_period_s", "mission_s", "sb_total_ms"])
            w.writerow([args.channel, args.interval_seconds, f"{sb_commit_mean:.3f}",
                        f"{sb_rate:.6f}", f"{sb_recovery_mean:.3f}",
                        f"{blackout_period if blackout_period != float('inf') else ''}",
                        args.mission_seconds, f"{sb_total:.3f}"])
        print(f"\nAppended result row to {args.out_csv}")


if __name__ == "__main__":
    main()
