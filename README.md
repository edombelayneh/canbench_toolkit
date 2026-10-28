# canbench: one fixed test battery for every CAN IDS dataset (protocol v1)

Run: `python3 -I run.py <DATASET> "<dataset folder>"` (e.g. `python3 -I run.py ROAD "/path/to/road 2"`).
Needs python3, numpy, pandas. Results go to `out/<DATASET>/results.json` and `id_counts.csv`; parsed frames are cached in `cache/<DATASET>/`.
Rule: use only files inside the dataset folder. Never use a summary table as a source.

## The five stages (same for every dataset)
1. **Integrity**: frames, duration vs metadata, monotonic time, gaps over 100 ms, ID set, IDs above 0x7FF, DLC mix, median vs mean inter-frame gap (clumped timestamps).
2. **Baseline profile**: built from the first 70% of every benign capture (per-ID period, byte min/max, max byte delta, per-second count range).
3. **Attack signature** (inside vs outside the attack window): bus rate, IDs only seen inside the window, top IDs by rate ratio, median gap, bytes changed vs previous frame of the same ID.
4. **Baseline detectors** scored on 1 s windows: false alarms on the last 30% of every benign capture, recall on each attack log's windows, first-alarm delay.
5. **Label audit** (only when per-frame labels exist): label share, first/last label vs the metadata window, labels outside the window.

## Fixed parameters (do not tune per dataset)
window 1 s | train = first 70% of each benign capture, test = last 30% | window alarm needs at least 3 flagged frames (frame-level detectors) | period: flag gap < 0.5 x benign 1st-percentile gap of that ID (IDs with at least 30 gaps) | rate: per-second count above 1.10 x benign max (+1) or below 0.90 x benign min (when min > 0) | payload range: any byte outside benign [min, max] of that ID | byte delta: any byte change vs previous same-ID frame above the benign max | ID whitelist: ID never seen in benign training | a detector is "usable" only if its benign window false-alarm rate is at most 5%; the combined detector ORs usable detectors only.

## Adding a dataset
Copy `adapters/template.py` to `adapters/<dataset>.py`. Provide `captures(root)` (name, role benign/attack, family, variant, intervals in elapsed seconds, meta, path), `load(cap)` returning normalized arrays (ts, id, data[n,8], dlc, t0), and optionally `frame_labels(cap)`. Then run `run.py`. Datasets with a single benign file work (the 70/30 split is inside each capture). Datasets without attack intervals get detector alarm rates only, no recall; if a dataset ships only per-frame labels, have the adapter build intervals with `core.intervals_from_labels(ts, label)`.

## Fixed doc entry (same section order for every dataset)
At a glance | What it does | How the data is organized | Attacks it contains | What is unique | Disadvantages | Why it was a milestone [I] | Baseline detectors | Examples and graphs | Questions worth saving [I]. Every claim tagged [D] file-stated, [C] computed, [I] inference. Add one row to the cross-dataset comparison table.

## Known limits of the protocol
The 70/30 split is inside each capture, so false-alarm rates are optimistic compared with a split by drive or by vehicle. Detectors are deliberately simple probes of how visible an attack is, not state-of-the-art IDS. Window-level scores cannot be compared with frame-level scores from papers.
