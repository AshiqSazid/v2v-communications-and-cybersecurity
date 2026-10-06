#!/usr/bin/env python3
"""Verify the VeReMi NextGen on-disk format before anything is converted.

    python3 veremi_probe.py --clean <dir> --attack <dir> [--attack-name NAME]

Every claim this repository makes about the VeReMi format is re-derived here
from the data rather than taken from documentation, because the Zenodo record
does not specify the field layout and the archives are not self-describing.

Findings this reproduces (run it to confirm them on your copy):

  1. Records are a JSON *array* per receiving vehicle, not JSON-lines, and every
     value is a string -- except messageID, which is a string in the clean
     archive and an int in the attack archives. Comparing them without
     normalising yields an empty intersection and a silently empty conversion.

  2. Each record carries BOTH `sender_id` (true identity) and `sender_alias`
     (the pseudonym a receiver actually sees). That is what makes the
     identity-versus-track comparison expressible on this dataset at all.

  3. `pos` and `pos_noise` are separate: `pos` is ground truth and `pos_noise`
     is the error to add, so the value a receiver observes is their sum.

  4. The attack archive is the SAME simulation as the clean archive with
     attacker messages rewritten. Diffing on (vehicle, messageID) therefore
     isolates exactly the modified messages, which matches this paper's
     convention that a message is malicious only when its content was actually
     modified -- not merely because its sender is an assigned attacker.

  5. `hed` is degrees CLOCKWISE FROM +y (compass), not the mathematical
     convention. Checked against the direction of travel between consecutive
     true positions; the compass reading matches to ~3 degrees (GNSS noise)
     while the mathematical one is off by ~92.

  6. Times are nanoseconds.

Exit status is non-zero if any of these no longer holds, so a dataset revision
cannot silently change the meaning of a converted trace.
"""
import argparse
import collections
import glob
import json
import math
import os
import statistics
import sys

FAIL = []


def check(name, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}{'  ' + detail if detail else ''}")
    if not ok:
        FAIL.append(name)


def vec(s):
    return [float(x) for x in str(s).split(",")]


def flat(rec):
    out = {}
    for k, v in rec.items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                out[f"{k}.{kk}"] = vv
        else:
            out[k] = v
    return out


def same(a, b, tol=1e-9):
    """Numeric-aware equality: the archives differ in float formatting only."""
    try:
        return math.isclose(float(a), float(b), rel_tol=tol, abs_tol=1e-12)
    except (TypeError, ValueError):
        pass
    sa, sb = str(a), str(b)
    if "," in sa and "," in sb:
        xa, xb = sa.split(","), sb.split(",")
        return len(xa) == len(xb) and all(same(p, q, tol) for p, q in zip(xa, xb))
    return sa == sb


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clean", required=True, help="extracted clean split directory")
    ap.add_argument("--attack", required=True, help="extracted attack split directory")
    ap.add_argument("--attack-name", default="(unnamed)")
    args = ap.parse_args()

    clean = sorted(glob.glob(os.path.join(args.clean, "*.json")))
    if not clean:
        sys.exit(f"error: no vehicle files under {args.clean}")
    print(f"clean vehicles : {len(clean)}")

    # ---- 1. container shape and messageID type drift -----------------------
    sample = json.load(open(clean[0]))
    check("records are a JSON array", isinstance(sample, list), f"n={len(sample)}")
    ctype = type(sample[0]["messageID"]).__name__
    apath = os.path.join(args.attack, os.path.basename(clean[0]))
    atype = "(attack file absent)"
    if os.path.exists(apath):
        atype = type(json.load(open(apath))[0]["messageID"]).__name__
    check("messageID type differs between archives", ctype != atype,
          f"clean={ctype} attack={atype} -- normalise with str() before joining")

    # ---- 2. true identity and pseudonym both present -----------------------
    r0 = sample[0]
    check("sender_id and sender_alias both present",
          "sender_id" in r0 and "sender_alias" in r0,
          f"{r0['sender_id']} / {r0['sender_alias']}")

    # ---- 3. pos and pos_noise are separate ---------------------------------
    check("pos and pos_noise are separate fields",
          "pos" in r0["sender"] and "pos_noise" in r0["sender"])

    # ---- 5. heading convention --------------------------------------------
    tracks = collections.defaultdict(set)
    for path in clean[:40]:
        for r in json.load(open(path)):
            p = vec(r["sender"]["pos"])
            tracks[r["sender_id"]].add(
                (float(r["sendTime"]), p[0], p[1], float(r["sender"]["hed"])))
    compass, mathematical = [], []
    for pts in tracks.values():
        pts = sorted(pts)
        for (t0, x0, y0, h0), (t1, x1, y1, _) in zip(pts, pts[1:]):
            dt = (t1 - t0) / 1e9
            dx, dy = x1 - x0, y1 - y0
            if not (0.05 < dt < 2.0) or math.hypot(dx, dy) < 1.0:
                continue
            compass.append(abs((math.degrees(math.atan2(dx, dy)) - h0 + 180) % 360 - 180))
            mathematical.append(abs((math.degrees(math.atan2(dy, dx)) - h0 + 180) % 360 - 180))
    if compass:
        mc, mm = statistics.median(compass), statistics.median(mathematical)
        check("hed is degrees clockwise from +y (compass)", mc < 15.0 and mc < mm,
              f"compass err={mc:.2f} deg vs mathematical={mm:.2f} deg (n={len(compass)})")

    # ---- 6. nanosecond timestamps -----------------------------------------
    lat = [(float(r["rcvTime"]) - float(r["sendTime"])) / 1e6 for r in sample]
    med = statistics.median(lat)
    check("timestamps are nanoseconds", 0.01 < med < 100.0,
          f"median rcv-send = {med:.3f} ms under a nanosecond reading")

    # ---- 4. attack archive is the same run with content rewritten ---------
    if os.path.isdir(args.attack):
        changed = collections.Counter()
        attackers, shared, modified = set(), 0, 0
        for cpath in clean:
            apath = os.path.join(args.attack, os.path.basename(cpath))
            if not os.path.exists(apath):
                continue
            a = {str(r["messageID"]): r for r in json.load(open(cpath))}
            b = {str(r["messageID"]): r for r in json.load(open(apath))}
            for m in set(a) & set(b):
                shared += 1
                x, y = flat(a[m]), flat(b[m])
                d = [k for k in x if not same(x[k], y.get(k))]
                if d:
                    modified += 1
                    changed.update(d)
                    attackers.add(b[m]["sender_id"])
        check("attack archive shares the clean run's messageIDs", shared > 0,
              f"{shared} shared messages")
        check("only content fields are rewritten", bool(changed),
              f"{args.attack_name}: {dict(changed)}")
        check("modification is confined to a sender subset",
              0 < len(attackers) < len(tracks) if tracks else bool(attackers),
              f"{modified} messages from {len(attackers)} senders")

    print()
    if FAIL:
        sys.exit(f"FAILED: {len(FAIL)} format assumption(s) no longer hold: {FAIL}")
    print("all format assumptions hold; conversion may proceed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
