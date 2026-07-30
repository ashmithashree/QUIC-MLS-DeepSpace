#!/usr/bin/env python3
# Note
# Reduces per-event CSV telemetry (produced by testbed-runner/src/main.rs)
# into the dissertation's own Security Budget metric:
#   SB = SSOR + RC x f_blackout
# where SSOR (steady-state overhead rate) sums commit_cpu + commit_net
# latency over steady-state commits / run duration, RC (recovery cost) is
# the mean reconnect_handshake_0rtt_accepted latency across blackout
# cycles, and f_blackout is observed blackout_start count / run duration.
#
# This metric and its definition are original to this dissertation
# (Section 5.1) not adapted from an external source. It deliberately
# supersedes an earlier draft formula that used estimated propagation-delay
# constants (SB = crypto_cycles x cycle_cost_ms + security_bytes x OWD_ms x
# blackout_freq); the current version uses only measured latency, since
# commit_net's timing already reflects RTT-weighted network cost
# empirically via the tc netem emulation, without a separate analytical
# OWD term.
#
# A failed recovery (blackout observed, zero successful reconnects) is
# deliberately left undefined/excluded from a cell's SB average rather
# than counted as zero-cost see the n_failed_recovery warning logic
# below, and Section 5.1's discussion of this choice.
#======================================================================================================================
from __future__ import annotations

import csv
import glob
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean


# --------------------------------------------------------------------------
# Channel name derivation from directory naming convention already in use:
#   sweep-results/          -> leo   (default, no suffix)
#   sweep-results-geo/      -> geo
#   sweep-results-lunar/    -> lunar
#   sweep-results-mars/     -> mars
# --------------------------------------------------------------------------
def channel_from_dir(path: str) -> str:
    base = os.path.basename(os.path.normpath(path))
    m = re.match(r"sweep-results(?:-(\w+))?$", base)
    if not m:
        return base  # fall back to whatever the directory is actually called
    return m.group(1) or "leo"


def interval_from_filename(path: str) -> int | None:
    m = re.search(r"_i(\d+)\.csv$", os.path.basename(path))
    return int(m.group(1)) if m else None


@dataclass
class RunMetrics:
    channel: str
    interval: int
    run_dir: str
    ssor_ms_per_s: float | None = None
    rc_ms: float | None = None
    f_blackout_per_s: float | None = None
    sb: float | None = None
    steady_bytes_per_s: float | None = None
    recovery_bytes_mean: float | None = None
    n_blackouts: int = 0
    n_recoveries: int = 0
    warnings: list[str] = field(default_factory=list)


def read_csv_rows(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def compute_run(alice_csv: str, channel: str, interval: int) -> RunMetrics:
    run_dir = os.path.dirname(alice_csv)
    m = RunMetrics(channel=channel, interval=interval, run_dir=run_dir)
    rows = read_csv_rows(alice_csv)
    if not rows:
        m.warnings.append(f"empty or missing CSV: {alice_csv}")
        return m

    for r in rows:
        r["epoch"] = int(r["epoch"]) if r["epoch"] else 0
        r["bytes"] = float(r["bytes"]) if r["bytes"] else 0.0
        r["latency_ms"] = float(r["latency_ms"]) if r["latency_ms"] else 0.0
        r["timestamp_ms"] = int(r["timestamp_ms"])

    t_start = rows[0]["timestamp_ms"]
    t_end = rows[-1]["timestamp_ms"]
    total_duration_s = max((t_end - t_start) / 1000.0, 1e-9)


    cpu_costs = [r["latency_ms"] for r in rows if r["event"] == "commit_cpu"]
    net_costs = [r["latency_ms"] for r in rows if r["event"] == "commit_net"]
    net_bytes = [r["bytes"] for r in rows if r["event"] == "commit_net"]

    if not cpu_costs and not net_costs:
        m.warnings.append("no steady-state commit_cpu/commit_net rows found")
    else:
        total_steady_cost_ms = sum(cpu_costs) + sum(net_costs)
        m.ssor_ms_per_s = total_steady_cost_ms / total_duration_s
        m.steady_bytes_per_s = sum(net_bytes) / total_duration_s if net_bytes else None

    n_blackouts = sum(1 for r in rows if r["event"] == "blackout_start")
    m.n_blackouts = n_blackouts
    m.f_blackout_per_s = n_blackouts / total_duration_s if n_blackouts else 0.0

    recovery_latencies = [
        r["latency_ms"] for r in rows if r["event"] == "reconnect_handshake_0rtt_accepted"
    ]
    recovery_bytes = [
        r["bytes"] for r in rows if r["event"] == "handshake_transcript_embedded"
    ]
    m.n_recoveries = len(recovery_latencies)
    if recovery_latencies:
        m.rc_ms = mean(recovery_latencies)
    elif n_blackouts:
        m.warnings.append(
            f"{n_blackouts} blackout(s) observed but 0 successful recoveries "
            "-- treating RC as undefined (livelock/failure), not zero"
        )
    if recovery_bytes:
        m.recovery_bytes_mean = mean(recovery_bytes)

    if m.ssor_ms_per_s is not None and m.f_blackout_per_s is not None:
        if m.rc_ms is not None:
            m.sb = m.ssor_ms_per_s + m.rc_ms * m.f_blackout_per_s
        elif n_blackouts == 0:

            m.sb = m.ssor_ms_per_s

    return m


def find_runs(search_dirs: list[str]) -> list[tuple[str, int, str]]:
    """Returns (channel, interval, alice_csv_path) for every run found."""
    found = []
    for d in search_dirs:
        channel = channel_from_dir(d)
        for alice_csv in sorted(glob.glob(os.path.join(d, "*", "alice_i*.csv"))):
            interval = interval_from_filename(alice_csv)
            if interval is None:
                continue
            found.append((channel, interval, alice_csv))
    return found


def main() -> None:
    search_dirs = sys.argv[1:] or sorted(glob.glob("sweep-results*"))
    if not search_dirs:
        print("No sweep-results* directories found in the current directory.",
              file=sys.stderr)
        print("Run this from the repo root, or pass directories explicitly:",
              file=sys.stderr)
        print("    python3 security_budget.py sweep-results sweep-results-mars",
              file=sys.stderr)
        sys.exit(1)

    runs = find_runs(search_dirs)
    if not runs:
        print("No alice_i<N>.csv files found under: " + ", ".join(search_dirs),
              file=sys.stderr)
        sys.exit(1)

    per_run: list[RunMetrics] = []
    for channel, interval, alice_csv in runs:
        m = compute_run(alice_csv, channel, interval)
        per_run.append(m)

    # --- per-run output ---
    with open("security_budget_per_run.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["channel", "interval_s", "run_dir", "ssor_ms_per_s", "rc_ms",
                    "f_blackout_per_s", "sb", "steady_bytes_per_s",
                    "recovery_bytes_mean", "n_blackouts", "n_recoveries", "warnings"])
        for m in per_run:
            w.writerow([m.channel, m.interval, m.run_dir,
                        _fmt(m.ssor_ms_per_s), _fmt(m.rc_ms), _fmt(m.f_blackout_per_s),
                        _fmt(m.sb), _fmt(m.steady_bytes_per_s), _fmt(m.recovery_bytes_mean),
                        m.n_blackouts, m.n_recoveries, "; ".join(m.warnings)])

    # --- averaged summary, one row per (channel, interval) ---
    groups: dict[tuple[str, int], list[RunMetrics]] = defaultdict(list)
    for m in per_run:
        groups[(m.channel, m.interval)].append(m)

    summary_rows = []
    for (channel, interval), ms in sorted(groups.items()):
        valid_sb = [m.sb for m in ms if m.sb is not None]
        valid_ssor = [m.ssor_ms_per_s for m in ms if m.ssor_ms_per_s is not None]
        valid_rc = [m.rc_ms for m in ms if m.rc_ms is not None]
        n_failed = sum(1 for m in ms if m.n_blackouts > 0 and m.rc_ms is None)
        summary_rows.append({
            "channel": channel,
            "interval_s": interval,
            "n_runs": len(ms),
            "n_failed_recovery": n_failed,
            "ssor_ms_per_s": mean(valid_ssor) if valid_ssor else None,
            "rc_ms": mean(valid_rc) if valid_rc else None,
            "sb": mean(valid_sb) if valid_sb else None,
        })

    with open("security_budget_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["channel", "interval_s", "n_runs", "n_failed_recovery",
                    "ssor_ms_per_s", "rc_ms", "sb"])
        for row in summary_rows:
            w.writerow([row["channel"], row["interval_s"], row["n_runs"],
                        row["n_failed_recovery"], _fmt(row["ssor_ms_per_s"]),
                        _fmt(row["rc_ms"]), _fmt(row["sb"])])

    # --- human-readable table ---
    print(f"{'channel':<8} {'interval_s':<11} {'runs':<6} {'failed':<8} "
          f"{'SSOR(ms/s)':<12} {'RC(ms)':<14} {'SB':<14}")
    for row in summary_rows:
        print(f"{row['channel']:<8} {row['interval_s']:<11} {row['n_runs']:<6} "
              f"{row['n_failed_recovery']:<8} {_fmt(row['ssor_ms_per_s']):<12} "
              f"{_fmt(row['rc_ms']):<14} {_fmt(row['sb']):<14}")

    print()
    print("Wrote security_budget_per_run.csv and security_budget_summary.csv")
    print()
    print("Security-Overhead Frontier: for each channel, the interval with the")
    print("lowest SB in security_budget_summary.csv is the frontier-optimal")
    print("commit interval for that channel.")
    any_failed = any(row["n_failed_recovery"] > 0 for row in summary_rows)
    if any_failed:
        print()
        print("WARNING: at least one (channel, interval) had blackouts with zero")
        print("successful recoveries. Those runs are EXCLUDED from the SB average")
        print("for that cell, not treated as SB=0 or dropped silently check")
        print("n_failed_recovery in the summary before reporting SB for that cell.")


def _fmt(x) -> str:
    if x is None:
        return ""
    return f"{x:.4f}"


if __name__ == "__main__":
    main()
