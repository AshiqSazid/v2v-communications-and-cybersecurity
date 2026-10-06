#!/usr/bin/env python3
"""Extract the source CSVs from V2V_Cyber_Risk_Final_Dataset.docx.

The .docx holds the dataset as four ID-keyed tables plus metadata. This joins
them on record_id and validates the result against the risk formulas stated in
the document, so a bad extraction fails loudly instead of silently.

Run both stages from the project root to regenerate the publication data:

    python3 data/extract_from_docx.py
    python3 data/enrich_dataset.py

This extraction stage writes the 37-column source scenarios and preserves the
DOCX's conceptual dictionary under a distinct ``*_source.csv`` name.  The
enrichment stage alone owns ``data/data_dictionary.csv`` because that file is
the normalized, one-row-per-column dictionary for the 49-column enriched CSV.
"""
import csv, re, sys, zipfile
from xml.etree import ElementTree as ET

NS = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
SRC = 'V2V_Cyber_Risk_Final_Dataset.docx'
SCENARIOS_OUT = 'data/v2v_cyber_risk_scenarios.csv'
SOURCE_DICTIONARY_OUT = 'data/data_dictionary_source.csv'

HEADER = [
    "record_id", "attack_type", "attack_category", "affected_field", "environment",
    "density", "driver_profile", "attack_intensity", "host_vehicles",
    "remote_vehicles", "target_component",
    "atd_source", "vulnerability", "interface", "cvss", "exploitability",
    "impact_safety", "impact_operational", "impact_privacy", "impact_financial",
    "impact_composite", "detection_difficulty",
    "likelihood", "exposure", "inherent_risk", "inherent_level",
    "mitigation_control", "mitigation_effectiveness_pct", "residual_risk",
    "residual_level", "safety_proxy",
    # Observed only for the four DoS scenarios (A13-C1..C4); blank elsewhere.
    "obs_apl_bytes", "obs_rate_mbps", "obs_pdr_pct", "obs_e2e_ms", "obs_sri",
    "obs_measured",
]

# Section 4 of the document.
BANDS = [(20, "Low"), (40, "Moderate"), (60, "High"), (80, "Very High"),
         (100, "Critical")]


def band(x):
    return next(name for hi, name in BANDS if x <= hi)


def main():
    body = ET.fromstring(zipfile.ZipFile(SRC).read('word/document.xml')) \
             .find('w:body', NS)

    def ptext(p):
        return ''.join(t.text or '' for t in p.iter('{%s}t' % NS['w']))

    def clean(s):
        return re.sub(r'\s+', ' ', s.replace(' ', ' ')).strip()

    def rows(tb):
        return [[clean(''.join(ptext(p) for p in c.findall('w:p', NS)))
                 for c in r.findall('w:tc', NS)]
                for r in tb.findall('w:tr', NS)]

    T = [rows(t) for t in body.findall('.//w:tbl', NS)]
    scen = {r[0]: r for r in T[8][1:]}    # attack + operational context
    vuln = {r[0]: r for r in T[9][1:]}    # vulnerability analogue + impact
    risk = {r[0]: r for r in T[10][1:]}   # scoring + mitigation
    dos = {r[0]: r for r in T[11][1:]}    # observed DoS benchmark

    order = [r[0] for r in T[8][1:]]
    assert order == [r[0] for r in T[9][1:]] == [r[0] for r in T[10][1:]], \
        "record_id order differs between tables -- join would be wrong"

    out = []
    for rid in order:
        d = dos.get(rid)
        out.append([rid] + scen[rid][1:11] + vuln[rid][1:12] + risk[rid][1:10] +
                   ([d[4], d[5], d[8], d[9], d[10], "1"]
                    if d else ["", "", "", "", "", "0"]))

    with open(SCENARIOS_OUT, 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(HEADER)
        w.writerows(out)
    with open(SOURCE_DICTIONARY_OUT, 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(["variable", "type", "definition", "status"])
        w.writerows(T[6][1:])

    # --- validate against the document's own formulas -------------------
    d = [dict(zip(HEADER, r)) for r in out]
    errs = []
    for r in d:
        L, I, E = float(r['likelihood']), float(r['impact_composite']), float(r['exposure'])
        if abs(round(L * I * E / 125 * 100, 1) - float(r['inherent_risk'])) > 0.15:
            errs.append(f"{r['record_id']}: inherent risk != L*I*E/125*100")
        eff = float(r['mitigation_effectiveness_pct'])
        if abs(round(float(r['inherent_risk']) * (1 - eff / 100), 1) - float(r['residual_risk'])) > 0.15:
            errs.append(f"{r['record_id']}: residual != inherent*(1-eff/100)")
        if band(float(r['inherent_risk'])) != r['inherent_level']:
            errs.append(f"{r['record_id']}: inherent_level banding")
        if band(float(r['residual_risk'])) != r['residual_level']:
            errs.append(f"{r['record_id']}: residual_level banding")

    print(f"{len(out)} scenarios x {len(HEADER)} columns, "
          f"{len({r['attack_type'] for r in d})} attack types")
    if errs:
        print(f"FAILED {len(errs)} consistency checks:")
        for e in errs[:10]:
            print("  ", e)
        sys.exit(1)
    print("all consistency checks passed "
          "(inherent formula, residual formula, both risk bandings)")
    print(f"source dictionary preserved as {SOURCE_DICTIONARY_OUT}; "
          "run data/enrich_dataset.py to regenerate the normalized dictionary")


if __name__ == '__main__':
    main()
