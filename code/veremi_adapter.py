#!/usr/bin/env python3
"""Convert a VeReMi NextGen split into this repository's replay format.

    python3 veremi_adapter.py --clean <clean split dir> --attack <attack split dir> \
        --attack-name constantPositionOffset --threshold 0.498 --output <run dir>

Emits `trace.csv` + `summary.csv`, the pair `baselines.py` already consumes, so
the external evaluation runs through the same replay as every in-generator
comparator rather than a parallel implementation.

Run `veremi_probe.py` first. Every mapping below depends on a format property it
verifies, and the archives are not self-describing.

Mapping decisions that are not mechanical, and why:

* `claimed_*` comes from the ATTACK archive and `oracle_true_*` from the CLEAN
  archive of the same simulation. That is what makes a message malicious only
  when its content was actually modified, matching the manuscript's convention
  rather than labelling everything an assigned attacker sent.
* Observed position is `pos + pos_noise`: VeReMi keeps ground truth and sensor
  error separate, so the value a receiver actually sees is their sum.
* Velocity is reconstructed as `spd * (sin(hed), cos(hed))` because `hed` is
  degrees CLOCKWISE FROM +y. This is not the mathematical convention and using
  that one rotates every velocity by ~90 degrees.
* `observable_source_ipv4` is a CONSTANT sentinel. VeReMi carries no link-layer
  identity, and filling it from ground truth would leak oracle information into
  a detector-visible field and make the identity-contested rule look perfect.
  That comparator must be excluded from VeReMi results.
* Coordinates are rebased to a local origin and the road extent is derived from
  the clean split, because the map-bounds check is parameterised for a 5 km
  synthetic highway and InTAS coordinates are UTM-like. The derived extent is
  printed so it can be passed to the replay.
* VeReMi NextGen contains no impersonation: every alias maps to exactly one true
  sender, including under the Sybil attack. `oracle_owner_is_attacker` therefore
  equals `oracle_source_is_attacker` and no pair is victim-exposed. Victim
  framing is not measurable on this dataset.
"""
from __future__ import annotations

import argparse
import csv
import glob
import itertools
import json
import math
import os
import sys
from pathlib import Path

TRACE_FIELDS = [
    "receiver_id", "rx_time", "receiver_true_x", "receiver_true_y",
    "observable_source_ipv4", "claimed_id", "claimed_seq", "claimed_tx_time",
    "claimed_x", "claimed_y", "claimed_vx", "claimed_vy",
    "oracle_source_id", "oracle_tx_seq", "oracle_tx_time",
    "oracle_true_x", "oracle_true_y", "oracle_true_vx", "oracle_true_vy",
    "oracle_source_is_attacker", "oracle_assigned_role", "oracle_attack_active",
    "oracle_message_is_malicious", "oracle_victim_id", "oracle_owner_is_attacker",
    "oracle_expected_receiver",
]

# VeReMi NextGen attack -> the manuscript's attacker role. Anything absent is
# converted but labelled `unmapped` and excluded from per-attack tables.
ROLE = {
    "constantPositionOffset": "constoffset",
    "dataReplay": "replay",
    "reversedHeading": "revheading",
    "dosAttack": "dos",
    "randomPositionOffset": "falsify",
    "trafficCongestionSybil": "sybil",
}

SENTINEL_IP = "0.0.0.0"      # no link-layer identity in VeReMi; see module docstring


def vec(s):
    return [float(x) for x in str(s).split(",")]


def vel(spd, hed):
    """hed is degrees clockwise from +y (verified by veremi_probe.py)."""
    r = math.radians(hed)
    return spd * math.sin(r), spd * math.cos(r)


def numeric_equal(a, b, tol=1e-9):
    try:
        return math.isclose(float(a), float(b), rel_tol=tol, abs_tol=1e-12)
    except (TypeError, ValueError):
        pass
    sa, sb = str(a), str(b)
    if "," in sa and "," in sb:
        xa, xb = sa.split(","), sb.split(",")
        return len(xa) == len(xb) and all(numeric_equal(p, q, tol) for p, q in zip(xa, xb))
    return sa == sb


def content_differs(clean, attack):
    """True when the attack archive rewrote this message's content."""
    for block in ("sender",):
        for key in ("pos", "spd", "hed", "acl", "pos_noise", "spd_noise", "hed_noise"):
            if not numeric_equal(clean[block].get(key), attack[block].get(key)):
                return True
    return False


def vid(name):
    """veh_4595 -> 4595, so ids stay integers as the replay expects."""
    return int(str(name).split("_")[-1])


def load_split(directory):
    out = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        out[vid(Path(path).stem)] = {str(r["messageID"]): r for r in json.load(open(path))}
    return out


def emit_veremi(trace_path: Path, clean_dir: Path, attack_dir: Path) -> int:
    """Inverse mapping: one of our traces -> VeReMi-shaped clean/attack archives.

    Exists so the forward conversion can be checked by round-trip on data whose
    correct answer is already known, rather than only on VeReMi itself where
    there is nothing to check it against.

    VeReMi keeps ground truth in `pos` and sensor error in `pos_noise`, and the
    observed value is their sum. The inverse must respect that or honest GPS
    noise is indistinguishable from falsification: putting the observed value
    straight into `pos` makes every message differ between the archives and the
    forward pass then labels the whole run malicious.

    So truth goes in `pos`/`spd`/`hed` on BOTH sides and the offset to the
    claimed value goes in the `_noise` fields, which are equal between archives
    for an honest message and differ exactly where the content was falsified.
    """
    clean_dir.mkdir(parents=True, exist_ok=True)
    attack_dir.mkdir(parents=True, exist_ok=True)
    per_clean, per_attack = {}, {}
    counter = itertools.count(1)
    csv.field_size_limit(10 ** 8)

    def polar(vx, vy):
        return math.hypot(vx, vy), math.degrees(math.atan2(vx, vy)) % 360.0

    def block(tx, ty, tspd, thed, dx, dy, dspd, dhed):
        return {"pos": f"{tx!r},{ty!r},0.0",
                "pos_noise": f"{dx!r},{dy!r},0.0",
                "spd": repr(tspd), "spd_noise": repr(dspd),
                "acl": "0.0", "acl_noise": "0.0",
                "hed": repr(thed), "hed_noise": repr(dhed),
                "driversProfile": "NORMAL"}

    with trace_path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            rx = int(row["receiver_id"])
            malicious = row["oracle_message_is_malicious"] in ("1", "true", "True")
            tx_, ty_ = float(row["oracle_true_x"]), float(row["oracle_true_y"])
            cx_, cy_ = float(row["claimed_x"]), float(row["claimed_y"])
            tspd, thed = polar(float(row["oracle_true_vx"]), float(row["oracle_true_vy"]))
            cspd, ched = polar(float(row["claimed_vx"]), float(row["claimed_vy"]))
            dx, dy = cx_ - tx_, cy_ - ty_
            dspd, dhed = cspd - tspd, ched - thed
            common = {"rcvTime": repr(float(row["rx_time"]) * 1e9),
                      "sendTime": repr(float(row["claimed_tx_time"]) * 1e9),
                      "sender_id": f"veh_{row['oracle_source_id']}",
                      "sender_alias": row["claimed_id"],
                      # Globally unique and NUMERIC, as VeReMi's are. Our
                      # claimed_seq is only per-sender, so it collides across
                      # senders within one receiver's file. The two are
                      # different namespaces: seq therefore cannot survive a
                      # round trip, and the fidelity check excludes it.
                      "messageID": str(next(counter)),
                      "receiver": block(float(row["receiver_true_x"]),
                                        float(row["receiver_true_y"]),
                                        0.0, 0.0, 0.0, 0.0, 0.0, 0.0)}
            # honest: identical offsets, so the archives agree. malicious: the
            # clean side carries no offset, so exactly those messages differ.
            per_clean.setdefault(rx, []).append(dict(common, sender=block(
                tx_, ty_, tspd, thed,
                0.0 if malicious else dx, 0.0 if malicious else dy,
                0.0 if malicious else dspd, 0.0 if malicious else dhed)))
            per_attack.setdefault(rx, []).append(dict(common, sender=block(
                tx_, ty_, tspd, thed, dx, dy, dspd, dhed)))
    for rx, recs in per_clean.items():
        (clean_dir / f"veh_{rx}.json").write_text(json.dumps(recs))
    for rx, recs in per_attack.items():
        (attack_dir / f"veh_{rx}.json").write_text(json.dumps(recs))
    return sum(len(v) for v in per_clean.values())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--emit-veremi", type=Path,
                    help="inverse: write VeReMi-shaped archives from one of our traces")
    ap.add_argument("--clean", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--attack-name", default="roundtrip")
    ap.add_argument("--threshold", type=float, default=0.498)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--prior", type=float, default=0.05)
    ap.add_argument("--decay-half-life", type=float, default=3.43096184915)
    ap.add_argument("--comm-range", type=float, default=300.0)
    ap.add_argument("--detector-gps-sigma", type=float, default=2.0)
    ap.add_argument("--spd-sigma", type=float, default=0.5)
    ap.add_argument("--warmup", type=float, default=5.0)
    args = ap.parse_args()

    if args.emit_veremi:
        n = emit_veremi(args.emit_veremi, Path(args.clean), Path(args.attack))
        print(f"wrote {n} receptions as VeReMi-shaped archives")
        return 0

    clean, attack = load_split(args.clean), load_split(args.attack)
    if not clean:
        sys.exit(f"error: no vehicle files under {args.clean}")

    # Attackers and onset are derived from the clean/attack diff, never assumed.
    # Two ways an attack shows up. Content attacks rewrite a message that also
    # exists in the clean run. Volume attacks (DoS) inject messages that have no
    # clean counterpart at all -- dropping those, as an earlier version of this
    # adapter did, silently converted the DoS arm into an attack-free one.
    modified, first_mod = {}, {}
    for rx, msgs in attack.items():
        for mid, rec in msgs.items():
            ref = clean.get(rx, {}).get(mid)
            injected = ref is None
            if injected or content_differs(ref, rec):
                sid = rec["sender_id"]
                modified.setdefault(sid, set()).add(mid)
                t = float(rec["rcvTime"])
                first_mod[sid] = min(first_mod.get(sid, t), t)

    times = [float(r["rcvTime"]) for m in attack.values() for r in m.values()]
    t0 = min(times)
    xs = [vec(r["sender"]["pos"])[0] for m in clean.values() for r in m.values()]
    ys = [vec(r["sender"]["pos"])[1] for m in clean.values() for r in m.values()]
    ox, oy = min(xs), min(ys)
    road_len, road_width = max(xs) - ox, max(ys) - oy

    args.output.mkdir(parents=True, exist_ok=True)
    rows = 0
    malicious_rx = 0
    # The replay requires a globally time-ordered stream, as the simulator emits.
    # Writing per-receiver blocks makes reception time jump backwards at every
    # receiver boundary and is rejected as non-monotone.
    emitted = []
    if True:
        for rx in sorted(attack):
            for mid, rec in sorted(attack[rx].items(), key=lambda kv: float(kv[1]["rcvTime"])):
                ref = clean.get(rx, {}).get(mid)
                # An injected message has no clean counterpart, so its own
                # reported state is the best available truth: a flooder is not
                # lying about where it is, it is sending too often.
                truth = ref if ref is not None else rec
                sid = rec["sender_id"]
                is_atk = sid in modified
                mal = mid in modified.get(sid, ())
                malicious_rx += mal
                sp, sc = rec["sender"], truth["sender"]
                cx, cy = vec(sp["pos"])[:2]
                nx, ny = vec(sp["pos_noise"])[:2]
                tx, ty = vec(sc["pos"])[:2]
                cvx, cvy = vel(float(sp["spd"]) + float(sp["spd_noise"]),
                               float(sp["hed"]) + float(sp["hed_noise"]))
                tvx, tvy = vel(float(sc["spd"]), float(sc["hed"]))
                rxp = vec(truth["receiver"]["pos"])[:2]
                rt = (float(rec["rcvTime"]) - t0) / 1e9
                st = (float(rec["sendTime"]) - t0) / 1e9
                active = is_atk and float(rec["rcvTime"]) >= first_mod[sid]
                emitted.append({
                    "receiver_id": rx, "rx_time": f"{rt:.9f}",
                    "receiver_true_x": f"{rxp[0]-ox:.6f}", "receiver_true_y": f"{rxp[1]-oy:.6f}",
                    "observable_source_ipv4": SENTINEL_IP,
                    "claimed_id": rec["sender_alias"], "claimed_seq": mid,
                    "claimed_tx_time": f"{st:.9f}",
                    "claimed_x": f"{cx+nx-ox:.6f}", "claimed_y": f"{cy+ny-oy:.6f}",
                    "claimed_vx": f"{cvx:.6f}", "claimed_vy": f"{cvy:.6f}",
                    "oracle_source_id": vid(sid), "oracle_tx_seq": mid,
                    "oracle_tx_time": f"{st:.9f}",
                    "oracle_true_x": f"{tx-ox:.6f}", "oracle_true_y": f"{ty-oy:.6f}",
                    "oracle_true_vx": f"{tvx:.6f}", "oracle_true_vy": f"{tvy:.6f}",
                    "oracle_source_is_attacker": int(is_atk),
                    "oracle_assigned_role": ROLE.get(args.attack_name, "unmapped"),
                    "oracle_attack_active": int(active),
                    "oracle_message_is_malicious": int(mal),
                    "oracle_victim_id": 0,
                    # no impersonation exists in VeReMi NextGen: every alias maps
                    # to exactly one true sender, so owner == source everywhere
                    "oracle_owner_is_attacker": int(is_atk),
                    # PDR-denominator flag, not a receiver id: "an honest
                    # sender was in range at true transmit time". VeReMi logs
                    # only actual receptions, so this is exactly "sender honest".
                    "oracle_expected_receiver": int(not is_atk),
                })
                rows += 1

    emitted.sort(key=lambda r: float(r["rx_time"]))
    with (args.output / "trace.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=TRACE_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(emitted)

    summary = {
        "schema": "v6", "n": len(clean), "frac": round(len(modified) / max(len(clean), 1), 6),
        "n_attackers": len(modified), "attack": ROLE.get(args.attack_name, "unmapped"),
        "run": 1, "sim_time": round(max(times) - t0, 6) / 1e9, "interval": 0.1,
        "detector": 1, "score_model": "reference", "mobility": "veremi",
        "null_ev": 0, "naive_th": 0, "prior": args.prior, "threshold": args.threshold,
        "decay": -1, "decay_half_life_s": args.decay_half_life, "warmup": args.warmup,
        "attack_start_s": 0, "comm_range": args.comm_range, "gps_sigma": args.detector_gps_sigma,
        "detector_gps_sigma": args.detector_gps_sigma, "spd_sigma": args.spd_sigma,
        "clock_sigma": 0.0, "bsm_bytes": 320, "eval_window_start_s": args.warmup,
    }
    with (args.output / "summary.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary), lineterminator="\n")
        w.writeheader()
        w.writerow(summary)

    print(f"wrote {rows} receptions to {args.output}/trace.csv")
    print(f"  attackers {len(modified)}/{len(clean)}  malicious receptions {malicious_rx}")
    print(f"  derived road extent: length={road_len:.1f} m width={road_width:.1f} m")
    print(f"  pass to the replay: --road-length {road_len:.1f} --road-width {road_width:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
