#!/usr/bin/env python3
"""Package the research artifact and deposit it on Zenodo.

    python3 publish_zenodo.py                 # dry run: build the archive, show metadata
    python3 publish_zenodo.py --upload        # create a DRAFT deposition (still retractable)
    python3 publish_zenodo.py --upload --publish   # mint the DOI (IRREVERSIBLE)

Token, in order of precedence:
    $ZENODO_TOKEN, or the first line of ~/.zenodo_token

Get one at https://zenodo.org/account/settings/applications/tokens/new/
with scopes: deposit:write, deposit:actions

Deliberate guards, because a published Zenodo DOI cannot be withdrawn:
  * --publish is required on top of --upload; uploading alone leaves a draft
    you can inspect and delete in the Zenodo UI;
  * refuses to run if .zenodo.json still holds the placeholder creator;
  * refuses to run if the frozen sweep is incomplete, so the archived results
    cannot disagree with the manuscript;
  * refuses to run on a dirty git tree, so the DOI names an exact commit.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
API = "https://zenodo.org/api"
SWEEP = ROOT / "code" / "results" / "v9" / "full"

# Everything the availability statement promises, and nothing else. Raw
# trace.csv files are excluded: >50 GB and exactly regenerable from source,
# seeds and plans.
INCLUDE = [
    "ieee.tex", "refs.bib", "ieee.pdf", "LICENSE", "README.md",
    "RESPONSE_TO_REVIEWERS.md", ".zenodo.json",
    "code/figures/*.pdf",
    "code/*.py", "code/*.cc", "code/*.sh", "code/*.md", "code/requirements.txt",
    "code/test/*",
    "code/results/v9/full/plans/*.tsv",
    "code/results/v9/full/analysis/*",
    "code/results/v9/full/manifest_v4.json",
    "code/results/v9/full/summary_v4.csv",
    "code/results/v9/full/pairs_v4.csv",
    "code/results/v9/full/validation_summary_v4.csv",
    "code/results/v9/full/validation_pairs_v4.csv",
    "code/results/v9/full/summary_schema_v4.csv",
    "code/results/v9/full/pair_schema_v4.csv",
    "code/results/v9/full/source_snapshot/*",
]


def die(msg):
    sys.exit(f"ERROR: {msg}")


def token():
    t = os.environ.get("ZENODO_TOKEN", "").strip()
    if t:
        return t
    p = Path.home() / ".zenodo_token"
    if p.exists():
        t = p.read_text().strip().splitlines()[0].strip()
        if t:
            return t
    die("no Zenodo token. Set $ZENODO_TOKEN or write one to ~/.zenodo_token\n"
        "       create at https://zenodo.org/account/settings/applications/tokens/new/\n"
        "       scopes required: deposit:write, deposit:actions")


def metadata():
    meta = json.loads((ROOT / ".zenodo.json").read_text())
    for c in meta.get("creators", []):
        if "REPLACE" in c.get("name", "").upper():
            die("`.zenodo.json` still contains the placeholder creator.\n"
                "       Zenodo records are permanent -- put the real author\n"
                "       metadata in before depositing.")
    meta.pop("notes", None)
    return meta


def check_sweep():
    manifest = SWEEP / "manifest_v4.json"
    if not manifest.exists():
        die(f"frozen sweep is incomplete: {manifest} does not exist.\n"
            "       Archiving now would publish results the paper does not report.")
    m = json.loads(manifest.read_text())
    return m


def check_clean_tree():
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        die(f"git tree is dirty ({len(dirty.splitlines())} paths). Commit first so "
            "the DOI names an exact revision.")
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()


def build_archive(out):
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for pattern in INCLUDE:
            for path in sorted(ROOT.glob(pattern)):
                if path.is_file():
                    z.write(path, path.relative_to(ROOT))
                    n += 1
                elif path.is_dir():
                    for sub in sorted(path.rglob("*")):
                        if sub.is_file():
                            z.write(sub, sub.relative_to(ROOT))
                            n += 1
    return n, out.stat().st_size


def api(method, url, tok, data=None, headers=None):
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("Authorization", f"Bearer {tok}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        die(f"Zenodo API {method} {url} -> {e.code}: {e.read().decode()[:400]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upload", action="store_true", help="create a draft deposition")
    ap.add_argument("--publish", action="store_true",
                    help="publish it and mint the DOI (IRREVERSIBLE)")
    args = ap.parse_args()

    meta = metadata()
    m = check_sweep()
    print(f"sweep manifest : {SWEEP/'manifest_v4.json'}")
    print(f"  runs completed: {m.get('completed_runs', '?')} "
          f"of planned {m.get('planned_runs', '?')}")
    print(f"title          : {meta['title'][:70]}...")
    print(f"creators       : {[c['name'] for c in meta['creators']]}")
    print(f"licence        : {meta.get('license')}")

    out = ROOT / "zenodo_artifact.zip"
    count, size = build_archive(out)
    print(f"archive        : {out.name}  ({count} files, {size/1e6:.1f} MB)")

    if not args.upload:
        print("\ndry run only. Re-run with --upload to create a draft deposition,\n"
              "then --upload --publish to mint the DOI.")
        return

    commit = check_clean_tree()
    print(f"commit         : {commit}")
    tok = token()

    dep = api("POST", f"{API}/deposit/depositions", tok, data=b"{}",
              headers={"Content-Type": "application/json"})
    dep_id, bucket = dep["id"], dep["links"]["bucket"]
    print(f"draft created  : {dep['links']['html']}")

    # Content-Length must be explicit: urllib will not infer it from a file
    # object, and Zenodo rejects the request as an empty file if it is absent.
    with out.open("rb") as fh:
        api("PUT", f"{bucket}/{out.name}", tok, data=fh,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Length": str(out.stat().st_size)})
    print("file uploaded")

    api("PUT", f"{API}/deposit/depositions/{dep_id}", tok,
        data=json.dumps({"metadata": meta}).encode(),
        headers={"Content-Type": "application/json"})
    print("metadata set")

    if not args.publish:
        print(f"\nDRAFT ready, not published: {dep['links']['html']}\n"
              "Inspect it, then re-run with --upload --publish to mint the DOI.")
        return

    pub = api("POST", f"{API}/deposit/depositions/{dep_id}/actions/publish", tok)
    print(f"\nPUBLISHED. DOI: {pub.get('doi')}")
    print(f"record        : {pub['links'].get('record_html')}")
    print("\nPaste the concept DOI into the availability statement in ieee.tex.")


if __name__ == "__main__":
    main()
