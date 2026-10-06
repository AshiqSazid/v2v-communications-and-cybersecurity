#!/usr/bin/env python3
"""Kinematic track association (Algorithm 2) as an offline replay.

The association lives in the ns-3 simulator, which generates its own mobility
and therefore cannot consume an external dataset. This module is the port that
lets the identity-versus-track comparison run on traces the simulator did not
produce -- VeReMi NextGen in particular.

It deliberately does NOT reimplement scoring. Association assigns each reception
to a track slot; the evidence update is then `baselines.update_state`, the same
function the in-generator comparators use, keyed on the track instead of the
claimed identity. Anything else would risk the port disagreeing with the paper
for reasons unrelated to association.

Faithfulness to `v2v_cybersecurity_v2.cc` is not assumed -- `--verify` replays
frozen v9 traces and checks this port reproduces the C++ track columns.

Semantics mirrored from the simulator, with source line references:
  * expiry: a track idle longer than TRACK_EXPIRY is archived and its slot
    released for reuse (ExpireTracks);
  * gating: residual <= TRACK_GATE_SIGMA*sigma_gps + VMAX*dt against a
    constant-velocity prediction from the track's last accepted observation;
  * selection: strictly-smallest residual, so ties resolve to the lowest slot;
  * a message older than a track's reference (dt < 0) cannot associate to it;
  * capacity: at most TRACK_MAX live slots, after which a message that matches
    no track is dropped from the track view (but still scored by identity);
  * a reused slot is a NEW track: its evidence starts from the prior again.
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import baselines

# Mirrored from v2v_cybersecurity_v2.cc; changing one here without the other is
# the failure this module's --verify mode exists to catch.
TRACK_GATE_SIGMA = 4.0
VMAX = 60.0
TRACK_EXPIRY = 20.0
TRACK_MAX = 4


@dataclass
class Slot:
    valid: bool = False
    instance: int = -1
    ref_x: float = 0.0
    ref_y: float = 0.0
    ref_t: float = 0.0
    vx: float = 0.0
    vy: float = 0.0
    last_time: float = -1.0


@dataclass
class TrackSet:
    """Live tracks for one (receiver, claimed identity) pair."""

    slots: list[Slot] = field(default_factory=list)
    next_instance: int = 0
    capacity_drops: int = 0

    def expire(self, now: float) -> None:
        for slot in self.slots:
            if slot.valid and slot.last_time >= 0.0 and (now - slot.last_time) > TRACK_EXPIRY:
                slot.valid = False

    def allocate(self) -> int | None:
        for slot in self.slots:
            if not slot.valid:
                slot.__init__()          # a reused slot is a new track
                slot.valid = True
                slot.instance = self.next_instance
                self.next_instance += 1
                return slot.instance
        if len(self.slots) >= TRACK_MAX:
            return None
        slot = Slot(valid=True, instance=self.next_instance)
        self.next_instance += 1
        self.slots.append(slot)
        return slot.instance

    def associate(self, obs, now: float, sigma_gps: float) -> int | None:
        """-> track instance id, or None when capacity is exhausted."""
        self.expire(now)
        chosen, best = None, math.inf
        for slot in self.slots:
            if not slot.valid:
                continue
            dt = obs.tx - slot.ref_t
            if dt < 0.0:
                continue                 # stale relative to this track
            px = slot.ref_x + slot.vx * dt
            py = slot.ref_y + slot.vy * dt
            residual = math.hypot(obs.x - px, obs.y - py)
            gate = TRACK_GATE_SIGMA * sigma_gps + VMAX * dt
            if residual <= gate and residual < best:
                best, chosen = residual, slot.instance
        if chosen is None:
            chosen = self.allocate()
            if chosen is None:
                self.capacity_drops += 1
                return None
        for slot in self.slots:
            if slot.instance == chosen:
                slot.ref_x, slot.ref_y, slot.ref_t = obs.x, obs.y, obs.tx
                slot.vx, slot.vy = obs.vx, obs.vy
                slot.last_time = now
                break
        return chosen


@dataclass
class TrackInfo:
    """Per-track evaluation truth. Never read by the association itself."""

    state: object = None
    carried_owner_genuine: bool = False
    carried_malicious: bool = False
    source_ids: set = field(default_factory=set)
    messages: int = 0


def evaluate_track_keyed(path: Path, schema, args, eval_start: float, warmup: float):
    """Replay one trace under kinematic-track keying.

    Returns {(rx, claimed): {instance: TrackInfo}} plus the capacity-drop count.
    """
    sets: dict[tuple[int, int], TrackSet] = defaultdict(TrackSet)
    tracks: dict[tuple[int, int], dict[int, TrackInfo]] = defaultdict(dict)
    prior_score = math.log(args.prior / (1.0 - args.prior))
    drops = 0
    for obs in baselines.observations(path, schema):
        pair = (obs.rx, obs.claimed)
        instance = sets[pair].associate(obs, obs.now, args.detector_gps_sigma)
        if instance is None:
            drops += 1
            continue
        info = tracks[pair].get(instance)
        if info is None:
            info = TrackInfo(state=baselines.State())
            info.state.score = prior_score
            info.state.owner_attacker = obs.owner_attacker
            tracks[pair][instance] = info
        baselines.update_state(info.state, obs, args, eval_start, warmup)
        info.messages += 1
        info.source_ids.add(obs.source)
        if obs.message_malicious:
            info.carried_malicious = True
        elif not obs.source_attacker:
            info.carried_owner_genuine = True
    return tracks, drops


def alerted(info: TrackInfo, threshold: float) -> bool:
    return info.state.peak_signals["sequential-score"] > threshold


def verify(runs_dir: Path, args, limit: int) -> int:
    """Replay frozen v9 traces and compare against the C++ track columns.

    This is the gate: the port is only usable if it reproduces the simulator on
    data where both can be evaluated.
    """
    checked = agree_owner = agree_honest = 0
    mismatches = []
    for run in sorted(p for p in runs_dir.iterdir() if p.is_dir())[:limit]:
        trace, pairs_csv = run / "trace.csv", run / "pairs.csv"
        if not (trace.exists() and pairs_csv.exists()):
            continue
        schema = baselines.read_schema(trace)
        meta = baselines.run_metadata(trace)
        eval_start, run_warmup = baselines.verify_replay_config(meta, args, meta.partition)
        tracks, _ = evaluate_track_keyed(trace, schema, args, eval_start, run_warmup)
        csv.field_size_limit(10 ** 8)
        for row in csv.DictReader(pairs_csv.open()):
            key = (int(row["receiver_id"]), int(row["claimed_id"]))
            infos = tracks.get(key, {})
            if not infos:
                continue
            owner = any(alerted(i, args.score_threshold)
                        for i in infos.values() if i.carried_owner_genuine)
            honest = any(alerted(i, args.score_threshold)
                         for i in infos.values()
                         if i.carried_owner_genuine and not i.carried_malicious)
            exp_owner = row.get("owner_track_alert") in ("1", "true", "True")
            exp_honest = row.get("honest_track_alert") in ("1", "true", "True")
            checked += 1
            agree_owner += owner == exp_owner
            agree_honest += honest == exp_honest
            if owner != exp_owner and len(mismatches) < 5:
                mismatches.append((run.name, key, owner, exp_owner))
    if not checked:
        sys.exit("error: no comparable pairs found")
    po = agree_owner / checked
    ph = agree_honest / checked
    print(f"pairs compared              : {checked}")
    print(f"owner-carrying-track alert  : {po:.4f} agreement")
    print(f"pure-honest-track alert     : {ph:.4f} agreement")
    for m in mismatches:
        print(f"  mismatch {m[0]} pair={m[1]} port={m[2]} cpp={m[3]}")
    ok = po >= 0.99 and ph >= 0.99
    print("\nPORT VERIFIED" if ok else "\nPORT DOES NOT REPRODUCE THE SIMULATOR")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", type=Path, required=True,
                    help="directory of frozen runs to replay and compare")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--threshold-json", type=Path, required=True)
    ap.add_argument("--baseline-parameters", type=Path, required=True,
                    help="frozen baseline parameter artefact, for replay settings")
    known, rest = ap.parse_known_args()
    # Reuse baselines' own parser so replay settings cannot drift between the
    # port and the comparators it is being checked against.
    sys.argv = [sys.argv[0],
                "--traces", str(known.verify),
                "--score-model", "reference",
                "--threshold-json", str(known.threshold_json),
                "--baseline-parameters", str(known.baseline_parameters),
                *rest]
    args = baselines.parse_args()
    return verify(known.verify, args, known.limit)


if __name__ == "__main__":
    raise SystemExit(main())
