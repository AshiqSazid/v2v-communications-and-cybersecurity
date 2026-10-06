# Minting the archival DOI

The manuscript's Data and Code Availability statement promises an archival
identifier. It cannot be created from this machine: it requires a Zenodo login,
and **a published Zenodo DOI is permanent and cannot be withdrawn.** That is a
decision to make deliberately, not a build step.

Everything else is ready. `.zenodo.json` in the repository root supplies the
record metadata automatically.

## Before you click anything

1. **Replace the `creators` block in `.zenodo.json`.** It currently holds an
   obvious placeholder. Zenodo will use it verbatim.
2. **Decide on timing.** Publishing a record with your names attached while the
   paper is under double-blind review breaks anonymity — the reviewer can find
   it. Two safe options:
   - publish the DOI **after acceptance**, and cite it at camera-ready; or
   - submit with an anonymised artifact link (`anonymous.4open.science`) and
     mint the Zenodo DOI at camera-ready.

   The manuscript already carries an `ANONYMITY WARNING` comment where the
   GitHub URL appears, for the same reason.

## The flow (about two minutes)

1. Sign in at <https://zenodo.org> with **Log in with GitHub**.
2. Go to <https://zenodo.org/account/settings/github/> and flip the switch on
   `AshiqSazid/ieee_V2V_cyber` to **On**.
3. Create a release in the repository:

   ```bash
   git tag -a v1.0.0 -m "Manuscript revision: frozen v9 sweep"
   git push origin v1.0.0
   ```

   Then publish it as a Release on GitHub (Zenodo only reacts to a published
   Release, not to a bare tag).
4. Zenodo mints the DOI within a minute or two. Take the **concept DOI** (the
   one that always resolves to the newest version), not the version-specific
   one.
5. Paste it into the availability statement in `ieee.tex`, replacing the
   sentence that currently says no DOI has been minted.

## What the archive must contain

Already true of the repository, but verify before releasing:

- `code/v2v_cybersecurity_v2.cc` — the exact simulator source
- `code/results/v9/full/plans/*.tsv` — frozen plans and seeds
- `code/results/v9/full/analysis/selected_threshold.json` — threshold + checksums
- `code/results/v9/full/summary_v4.csv`, `pairs_v4.csv` — merged results
- `code/results/v9/full/manifest_v4.json` — source/binary/plan/result hashes
- `code/README.md` — one runnable command per table and figure
- `LICENSE` — MIT

Raw `trace.csv` files are deliberately excluded: >50 GB, exactly regenerable
from the shipped source, seeds and plans.
