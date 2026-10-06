#!/usr/bin/env python3
"""Build an urban SUMO scenario and export ns-2 mobility for ns-3.

The manuscript's mobility is a straight 5 km highway at constant velocity,
which is its weakest evaluation assumption: intersections, stops, turns and
occlusion are exactly where a kinematic plausibility check is hardest. This
produces the missing input -- a signalised Manhattan grid with car-following
and turning traffic -- in the ns-2 trace format ``Ns2MobilityHelper`` reads, so
the existing simulator can be pointed at it without a SUMO/ns-3 co-simulation.

It is deliberately an offline trace, not a Veins-style coupling: the detector
is passive and transmits nothing, so vehicle motion cannot depend on the
network, and a replayed trace is therefore equivalent to live coupling here
while being far simpler to freeze and ship.

    .venv-ml/bin/python make_urban_scenario.py --out scenarios/urban \\
        --grid 5 --block 200 --vehicles 70 --duration 60 --seed 1

Then run the simulator with the trace. The road-bound check must be widened to
the grid extent, since the map predicate assumes a single carriageway:
    --mobility=ns2 --mobilityTrace=scenarios/urban/urban.ns2.tcl \\
    --roadLength=<grid*block> --roadWidth=<grid*block>
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import sumolib


def tool(name: str) -> Path:
    root = Path(sumolib.__file__).resolve().parent.parent / "sumo" / "tools"
    path = root / name
    if not path.exists():
        raise SystemExit(f"missing SUMO tool: {path}")
    return path


def run(cmd, **kw):
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}\n{proc.stderr[-2500:]}")
    return proc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--grid", type=int, default=5, help="intersections per side")
    ap.add_argument("--block", type=int, default=200, help="block length, m")
    ap.add_argument("--vehicles", type=int, default=70)
    ap.add_argument("--duration", type=int, default=60, help="seconds")
    ap.add_argument("--step", type=float, default=0.1, help="FCD sampling, s")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    net = args.out / "urban.net.xml"
    trips = args.out / "urban.trips.xml"
    routes = args.out / "urban.rou.xml"
    fcd = args.out / "urban.fcd.xml"
    ns2 = args.out / "urban.ns2.tcl"

    # Signalised grid: the point is intersections and turns, not map realism.
    run([sumolib.checkBinary("netgenerate"), "--grid",
         "--grid.number", str(args.grid), "--grid.length", str(args.block),
         "--default.lanenumber", "2", "--tls.guess", "true",
         "--default.speed", "13.9",            # 50 km/h urban
         "--no-turnarounds", "true",
         "--output-file", str(net), "--seed", str(args.seed)])

    period = max(args.duration / max(args.vehicles, 1), 0.05)
    run([sys.executable, str(tool("randomTrips.py")), "-n", str(net),
         "-o", str(trips), "-r", str(routes),
         "-b", "0", "-e", str(args.duration), "-p", f"{period:.4f}",
         "--seed", str(args.seed), "--validate",
         "--trip-attributes", 'departSpeed="max" departLane="best"'])

    run([sumolib.checkBinary("sumo"), "-n", str(net), "-r", str(routes),
         "--begin", "0", "--end", str(args.duration),
         "--step-length", str(args.step),
         "--fcd-output", str(fcd), "--seed", str(args.seed),
         "--no-step-log", "true", "--time-to-teleport", "-1"])

    env = dict(os.environ, SUMO_HOME=str(Path(sumolib.__file__).parent.parent / "sumo"))
    run([sys.executable, str(tool("traceExporter.py")), "--fcd-input", str(fcd),
         "--ns2mobility-output", str(ns2)], env=env)

    # Report what the simulator needs to be told, and what it will see.
    import re
    node_re = re.compile(r"\$node_\((\d+)\)")
    dest_re = re.compile(r'setdest ([-\d.]+) ([-\d.]+) ([-\d.]+)"')
    xs, ys, ids, speeds = [], [], set(), []
    for line in ns2.read_text().splitlines():
        m = node_re.search(line)
        if m:
            ids.add(m.group(1))
        d = dest_re.search(line)
        if d:
            xs.append(float(d.group(1)))
            ys.append(float(d.group(2)))
            speeds.append(float(d.group(3)))
        elif " set X_ " in line:
            xs.append(float(line.split()[-1]))
        elif " set Y_ " in line:
            ys.append(float(line.split()[-1]))
    print(f"net        {net}")
    print(f"routes     {routes}")
    print(f"ns-2 trace {ns2}  ({ns2.stat().st_size/1e6:.1f} MB)")
    print(f"vehicles   {len(ids)}   waypoints {len(speeds)}")
    if speeds:
        moving = [s for s in speeds if s > 0.1]
        print(f"speed      mean {sum(speeds)/len(speeds):.1f} m/s, "
              f"max {max(speeds):.1f};  {100*(1-len(moving)/len(speeds)):.0f}% of "
              f"samples stationary (queued at lights)")
    if xs and ys:
        print(f"extent     x [{min(xs):.0f}, {max(xs):.0f}]  "
              f"y [{min(ys):.0f}, {max(ys):.0f}] m")
        print(f"\nRun the simulator with --roadLength={max(xs):.0f} "
              f"--roadWidth={max(ys):.0f} so the map-bounds check matches the grid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
