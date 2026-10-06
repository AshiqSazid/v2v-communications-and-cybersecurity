#!/usr/bin/env python3
"""Enrich the 60-scenario risk dataset with the fields this project needs.

Reads  data/v2v_cyber_risk_scenarios.csv   (extracted from the .docx)
Writes data/v2v_cyber_risk_enriched.csv    (+ 12 derived columns)
       data/stride_dread_table.csv         (drop-in replacement for g_dread[])
       data/detector_coverage.csv          (check-vs-attack matrix)
       data/data_dictionary.csv            (one row per enriched CSV column)

EVERY added column is DERIVED, not observed. The derivation rules are stated
below and are deterministic, so a reviewer can reproduce or reject them. None
of these are measurements and the paper must not present them as such.

    python3 data/enrich_dataset.py     # run from the project root
"""
import csv
import statistics as st

IN = 'data/v2v_cyber_risk_scenarios.csv'

# --------------------------------------------------------------------------
# 1. attack_category -> the Stride enum used in v2v_cybersecurity_v2.cc
# --------------------------------------------------------------------------
STRIDE = {
    'Integrity / spoofing':            'S_SPOOFING',
    'Authenticity / identity':         'S_SPOOFING',
    'Integrity / falsification':       'S_TAMPERING',
    'Integrity / event falsification': 'S_TAMPERING',
    'Freshness / replay':              'S_REPUDIATION',
    'Availability / timing':           'S_REPUDIATION',
    'Availability / flooding':         'S_DOS',
}

# Some source-dataset categories are broader than the evidence consequence
# used by the detector.  In particular, a reversed velocity vector changes
# message content while retaining the sender identity, so the implemented
# heading-consistency check attributes it to Tampering rather than Spoofing.
STRIDE_OVERRIDES = {
    'Reversed Heading': 'S_TAMPERING',
}

# --------------------------------------------------------------------------
# 2. Detector coverage: which of the seven plausibility checks in
#    v2v_cybersecurity_v2.cc can actually fire for each attack.
#
#    Derived from attack SEMANTICS, not from measurement. The reasoning for
#    each is in the third field and must survive review on its own merit.
#
#    'full'    -- the attack necessarily violates the check
#    'partial' -- fires only under some parameterisations
#    'none'    -- no implemented check responds to this attack
# --------------------------------------------------------------------------
COVERAGE = {
    'Time-Delay Attack': (
        'CHK_STALENESS', 'full',
        'Delayed delivery inflates (now - txTime) beyond MAX_AGE.'),
    'Constant Position Offset': (
        'CHK_MAP_BOUNDS', 'partial',
        'A fixed offset keeps the trajectory internally consistent: implied '
        'speed stays plausible, so POSITION_JUMP and SPEED_MISMATCH never '
        'fire. Only detected if the offset pushes the claim off-road.'),
    'Random Position Offset': (
        'CHK_POSITION_JUMP', 'full',
        'Re-randomised position each beacon implies impossible speed.'),
    'Position Mirroring': (
        'CHK_MAP_BOUNDS', 'partial',
        'Mirrored track is smooth and self-consistent; detected only when the '
        'mirrored position lands outside the road polygon.'),
    'Constant Speed Offset': (
        'CHK_SPEED_MISMATCH', 'full',
        'Asserted speed diverges from displacement-implied speed.'),
    'Random Speed Offset': (
        'CHK_SPEED_MISMATCH', 'full',
        'Asserted speed diverges from displacement-implied speed.'),
    'Zero-Speed Report': (
        'CHK_SPEED_MISMATCH', 'full',
        'Claims v=0 while position advances.'),
    'Sudden Constant Speed': (
        'CHK_SPEED_MISMATCH', 'partial',
        'Fires while asserted and implied speed disagree; a slow ramp inside '
        'SPEED_TOL = 15 m/s evades it.'),
    'Reversed Heading': (
        'CHK_HEADING', 'full',
        'The implemented direction-consistency check compares the asserted '
        'velocity vector with displacement between sufficiently separated '
        'beacons; reversing the vector makes their cosine negative.'),
    'Feigned Braking': (
        '', 'none',
        'GAP. Kinematics remain physically plausible; only the event claim is '
        'false. Needs corroboration against neighbour reports.'),
    'Acceleration Multiplication': (
        'CHK_SPEED_MISMATCH', 'partial',
        'Detected once the scaled acceleration drives asserted speed past '
        'SPEED_TOL; small multipliers evade it.'),
    'Sudden Stop': (
        '', 'none',
        'GAP. A stop is physically achievable, so no plausibility check is '
        'violated. Needs event corroboration or deceleration-rate bounds.'),
    'Denial-of-Service Attack': (
        'CHK_RATE', 'full',
        'Beacon rate exceeds RATE_LIMIT = 20 msg/s per identity.'),
    'Traffic-Congestion Sybil': (
        '', 'none',
        'GAP. Each fabricated identity is individually plausible. Needs an '
        'identity-density or co-location check across neighbours.'),
    'Data-Replay Attack': (
        'CHK_REPLAY', 'full',
        'Duplicate sequence number and non-monotonic timestamp.'),
}

INTENSITY = {'Low': 3, 'Moderate': 5, 'High': 8, 'Severe': 10}

# The source dataset has no Information Disclosure or Elevation of Privilege
# scenarios.  Keep those two entries explicit (rather than silently borrowing
# another class) and label them as author-elicited values everywhere they are
# exported.  Component order is D, R, E, A, D.
ELICITED_DREAD = {
    'S_INFO_DISCLOSURE': (8, 6, 2, 8, 2),
    'S_ELEVATION': (8, 6, 2, 9, 2),
}


def compact_number(value):
    """Write reproducible decimal means without binary-float noise."""
    return f'{value:.6f}'.rstrip('0').rstrip('.')


def scale(v, lo, hi):
    """Map v from [lo,hi] onto 1..10, clamped."""
    return max(1, min(10, round(1 + 9 * (v - lo) / (hi - lo))))


def main():
    rows = list(csv.DictReader(open(IN)))

    for r in rows:
        r['stride_class'] = STRIDE_OVERRIDES.get(
            r['attack_type'], STRIDE[r['attack_category']])

        # ---- DREAD components, 1..10 (Microsoft's scale) -----------------
        # Damage           <- composite impact (1-5), doubled
        # Reproducibility  <- attack intensity of the scenario
        # Exploitability   <- CVSS exploitability sub-score (1.2-3.89)
        # Affected users   <- exposure (1-5), doubled
        # Discoverability  <- inverse of detection difficulty (1-5)
        r['dread_damage'] = min(10, int(float(r['impact_composite']) * 2))
        r['dread_reproducibility'] = INTENSITY[r['attack_intensity']]
        r['dread_exploitability'] = scale(float(r['exploitability']), 1.2, 3.89)
        r['dread_affected_users'] = min(10, int(float(r['exposure']) * 2))
        r['dread_discoverability'] = scale(6 - float(r['detection_difficulty']), 1, 5)
        total = sum(int(r[f'dread_{k}']) for k in
                    ('damage', 'reproducibility', 'exploitability',
                     'affected_users', 'discoverability'))
        r['dread_total'] = total
        r['dread_impact_normalised'] = round(total / 50, 3)

        chk, cov, why = COVERAGE[r['attack_type']]
        r['detector_check'] = chk
        r['detector_coverage'] = cov
        r['detector_rationale'] = why
        r['detector_gap'] = '1' if cov == 'none' else '0'

    added = ['stride_class', 'dread_damage', 'dread_reproducibility',
             'dread_exploitability', 'dread_affected_users',
             'dread_discoverability', 'dread_total', 'dread_impact_normalised',
             'detector_check', 'detector_coverage', 'detector_rationale',
             'detector_gap']
    header = list(rows[0].keys())

    with open('data/v2v_cyber_risk_enriched.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=header, lineterminator='\n')
        w.writeheader()
        w.writerows(rows)

    # ---- g_dread[] replacement, aggregated per STRIDE class --------------
    order = ['S_SPOOFING', 'S_TAMPERING', 'S_REPUDIATION',
             'S_INFO_DISCLOSURE', 'S_DOS', 'S_ELEVATION']
    with open('data/stride_dread_table.csv', 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(['stride_class', 'n_scenarios', 'damage', 'reproducibility',
                    'exploitability', 'affected_users', 'discoverability',
                    'total', 'normalised_impact', 'source'])
        for s in order:
            grp = [r for r in rows if r['stride_class'] == s]
            if not grp:
                comp = ELICITED_DREAD[s]
                total = sum(comp)
                w.writerow([s, 0] + list(comp) + [total,
                            compact_number(total / 50),
                            'author-elicited; no matching source-dataset '
                            'scenarios'])
                continue
            comp = [st.mean(int(r[f'dread_{k}']) for r in grp)
                    for k in ('damage', 'reproducibility', 'exploitability',
                              'affected_users', 'discoverability')]
            total = sum(comp)
            w.writerow([s, len(grp)] + [compact_number(v) for v in comp]
                       + [compact_number(total),
                          compact_number(total / 50),
                          'derived from source dataset (component-wise '
                          'arithmetic means over scenarios; no pre-sum '
                          'rounding)'])

    # ---- coverage matrix -------------------------------------------------
    with open('data/detector_coverage.csv', 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(['attack_type', 'stride_class', 'detector_check',
                    'coverage', 'is_gap', 'rationale'])
        seen = set()
        for r in rows:
            if r['attack_type'] in seen:
                continue
            seen.add(r['attack_type'])
            w.writerow([r['attack_type'], r['stride_class'],
                        r['detector_check'] or '-', r['detector_coverage'],
                        r['detector_gap'], r['detector_rationale']])

    # ---- regenerate the complete data dictionary -------------------------
    # The supplied document used title-case conceptual labels that did not
    # match the actual CSV schema (and combined several columns into one
    # dictionary row).  Emit one exact row per machine-readable column so
    # header coverage is testable and the generator remains idempotent.
    dictionary_path = 'data/data_dictionary.csv'
    base_dictionary = [
        ['record_id', 'Text', 'Unique attack-context scenario key', 'Generated'],
        ['attack_type', 'Categorical', 'One of 15 VeReMi NextGen attack types',
         'Source taxonomy'],
        ['attack_category', 'Categorical',
         'Integrity, authenticity, freshness, or availability grouping',
         'Derived taxonomy'],
        ['affected_field', 'Categorical', 'V2V message field affected',
         'Source taxonomy'],
        ['environment', 'Categorical', 'Urban or highway context',
         'Scenario design'],
        ['density', 'Ordinal', 'Low or high traffic density', 'Scenario design'],
        ['driver_profile', 'Categorical', 'Cautious, normal, or aggressive',
         'Scenario design'],
        ['attack_intensity', 'Ordinal', 'Low, moderate, high, or severe',
         'Scenario design'],
        ['host_vehicles', 'Integer', 'Host-vehicle count for the context',
         'Safety-benchmark design'],
        ['remote_vehicles', 'Integer', 'Remote-vehicle count for the context',
         'Safety-benchmark design'],
        ['target_component', 'Categorical', 'Vehicle/communication component at risk',
         'Derived from attack semantics and Acti ontology'],
        ['atd_source', 'Text', 'Representative AutomotiveTD source-record identifier',
         'Observed source identifier'],
        ['vulnerability', 'Text', 'CVE when available, otherwise AutomotiveTD ID',
         'Observed source identifier'],
        ['interface', 'Categorical', 'Representative attack interface',
         'AutomotiveTD analogue'],
        ['cvss', 'Numeric', 'Representative vulnerability CVSS base score',
         'AutomotiveTD analogue'],
        ['exploitability', 'Numeric',
         'CVSS v3 exploitability or normalized CVSS v2 exploitability',
         'Observed/normalized'],
        ['impact_safety', 'Ordinal 1-5', 'Potential physical-safety consequence',
         'Derived'],
        ['impact_operational', 'Ordinal 1-5',
         'Service and vehicle-function consequence', 'Derived'],
        ['impact_privacy', 'Ordinal 1-5', 'Location, identity, or data consequence',
         'Derived'],
        ['impact_financial', 'Ordinal 1-5', 'Repair, fraud, or loss consequence',
         'Derived'],
        ['impact_composite', 'Ordinal 1-5',
         'Supplied multidimensional composite impact', 'Calculated'],
        ['detection_difficulty', 'Ordinal 1-5',
         'Difficulty of identifying the attack', 'Expert-coded assumption'],
        ['likelihood', 'Ordinal 1-5', 'Estimated exploit/occurrence likelihood',
         'Calculated'],
        ['exposure', 'Ordinal 1-5', 'Accessibility of the attack surface',
         'Calculated'],
        ['inherent_risk', 'Numeric 0-100', 'Risk before controls', 'Calculated'],
        ['inherent_level', 'Categorical', 'Band assigned to inherent risk',
         'Calculated'],
        ['mitigation_control', 'Text', 'Recommended control bundle',
         'Acti/literature informed'],
        ['mitigation_effectiveness_pct', 'Numeric percent',
         'Assumed mitigation effectiveness', 'Derived assumption'],
        ['residual_risk', 'Numeric 0-100', 'Risk after assumed mitigation',
         'Calculated'],
        ['residual_level', 'Categorical', 'Band assigned to residual risk',
         'Calculated'],
        ['safety_proxy', 'Numeric 0-1',
         'Comparable safety-severity proxy across attack types', 'Calculated'],
        ['obs_apl_bytes', 'Numeric or blank',
         'Observed DoS attack packet length; blank otherwise',
         'Observed for DoS only'],
        ['obs_rate_mbps', 'Numeric or blank',
         'Observed DoS attack rate; blank otherwise', 'Observed for DoS only'],
        ['obs_pdr_pct', 'Numeric or blank',
         'Observed DoS packet-delivery ratio; blank otherwise',
         'Observed for DoS only'],
        ['obs_e2e_ms', 'Numeric or blank',
         'Observed DoS end-to-end latency; blank otherwise',
         'Observed for DoS only'],
        ['obs_sri', 'Numeric or blank',
         'Observed DoS Safety Risk Index; blank otherwise',
         'Observed for DoS only'],
        ['obs_measured', 'Binary',
         '1 when the network/safety fields are observed rather than proxied',
         'Provenance flag'],
    ]
    with open(dictionary_path, 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(['variable', 'type', 'definition', 'status'])
        for row in base_dictionary:
            w.writerow(row)
        w.writerows([
            ['stride_class', 'Categorical',
             'attack_category mapped onto the Stride enum in '
             'v2v_cybersecurity_v2.cc', 'Derived (deterministic mapping)'],
            ['dread_damage', 'Integer 1-10',
             'impact_composite (1-5) x 2', 'Derived'],
            ['dread_reproducibility', 'Integer 1-10',
             'attack_intensity mapped Low=3, Moderate=5, High=8, Severe=10',
             'Derived (assumption)'],
            ['dread_exploitability', 'Integer 1-10',
             'CVSS exploitability sub-score rescaled from [1.2, 3.89] to 1-10',
             'Derived from observed CVSS'],
            ['dread_affected_users', 'Integer 1-10',
             'exposure (1-5) x 2', 'Derived'],
            ['dread_discoverability', 'Integer 1-10',
             'inverse of detection_difficulty, rescaled to 1-10', 'Derived'],
            ['dread_total', 'Integer 5-50',
             'sum of the five DREAD components', 'Derived'],
            ['dread_impact_normalised', 'Float 0-1',
             'dread_total / 50; the ordinal impact term in the post-detection '
             'priority index Q = S_peak x Impact',
             'Derived'],
            ['detector_check', 'Categorical',
             'which plausibility check in v2v_cybersecurity_v2.cc responds to '
             'this attack; blank if none does', 'Derived (analytical)'],
            ['detector_coverage', 'Categorical',
             'full = attack necessarily violates the check; partial = only '
             'under some parameterisations; none = not detectable by the '
             'current check set', 'Derived (analytical)'],
            ['detector_rationale', 'Text',
             'justification for the coverage judgement', 'Derived (analytical)'],
            ['detector_gap', 'Binary',
             '1 if no implemented check responds to this attack',
             'Derived (analytical)'],
        ])

    n_gap = len({r['attack_type'] for r in rows if r['detector_gap'] == '1'})
    n_part = len({r['attack_type'] for r in rows
                  if r['detector_coverage'] == 'partial'})
    n_full = 15 - n_gap - n_part
    print(f"enriched: {len(rows)} rows, +{len(added)} derived columns")
    print(f"detector coverage over the 15 VeReMi NextGen attacks: "
          f"{n_full} full, {n_part} partial, {n_gap} NOT COVERED")


if __name__ == '__main__':
    main()
