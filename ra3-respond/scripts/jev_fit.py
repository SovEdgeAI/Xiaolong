#!/usr/bin/env python3
"""Fit AnyJev L1 / L2 artifacts on teacher labels and evaluate them against L0.

Input: the JSONL written by scripts/jev_teacher_labels.py. Each alert is a
`train` or `test` record; each candidate action is one yes/no question of the
local decider, labeled "yes" / "no" (or null where the teachers disagreed,
which is skipped).

  L1  temperature scaling over the L0 probabilities   (Decider.calibrate)
  L2  closed-form head on the hidden state            (Decider.fit_head, anyjev >= 0.2)

Only `train` records are used for fitting; `test` records measure accuracy,
expected calibration error and Brier score at L0 and at every fitted level.
Artifacts go to --out (serve with JEV_ARTIFACTS=<out>); the evaluation report
goes next to it as <out>.report.json.

--label-source rule uses the policy's rule voter instead of the teachers: free,
for exercising the pipeline before paying for teacher labels.

Usage:
  LLM_MODEL=anyjev .venv/bin/python scripts/jev_fit.py --labels artifacts/teacher_labels.jsonl \\
      --levels L1,L2 --out artifacts/jev_artifacts.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))
os.environ.pop("JEV_ARTIFACTS", None)  # fit from scratch, never on top of served artifacts

import jev_decider  # noqa: E402


def load(path: str, source: str) -> dict[str, dict[str, list]]:
    """question name -> split -> [(state, label)], label 0 = Yes, 1 = No (noul option index)."""
    data: dict[str, dict[str, list]] = {}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            state = jev_decider.incident_state(r["client_id"], r["attack_type"], r["severity"],
                                               r["confidence"], r["metadata"])
            for a in r["candidates"]:
                if source == "rule":
                    y = 0 if r["rule"][a] else 1
                else:
                    lab = r["labels"].get(a)
                    if lab is None:
                        continue
                    y = 0 if lab == "yes" else 1
                data.setdefault(a, {"train": [], "test": []})[r["split"]].append((state, y))
    return data


def metrics(p_yes: np.ndarray, y: np.ndarray, bins: int = 10) -> dict:
    """y: 1 = Yes. ECE over the confidence of the predicted side."""
    pred = (p_yes >= 0.5).astype(int)
    conf = np.where(pred == 1, p_yes, 1 - p_yes)
    correct = (pred == y).astype(float)
    ece = 0.0
    for lo in np.linspace(0.5, 1.0, bins, endpoint=False):
        m = (conf >= lo) & (conf < lo + 0.5 / bins) if lo < 0.95 else (conf >= lo)
        if m.any():
            ece += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return {"n": int(len(y)), "accuracy": round(float(correct.mean()), 4), "ece": round(float(ece), 4),
            "brier": round(float(np.mean((p_yes - y) ** 2)), 4), "mean_confidence": round(float(conf.mean()), 4)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--label-source", choices=["teacher", "rule"], default="teacher")
    ap.add_argument("--levels", default="L1,L2", help="comma-separated subset of L1,L2")
    ap.add_argument("--questions", help="only these actions (comma-separated)")
    ap.add_argument("--min-n", type=int, default=20, help="min train labels per question")
    ap.add_argument("--min-class", type=int, default=5, help="min train labels of the rarer class")
    ap.add_argument("--no-eval", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "artifacts", "jev_artifacts.json"))
    args = ap.parse_args()

    levels = [lv.strip() for lv in args.levels.split(",") if lv.strip()]
    data = load(args.labels, args.label_source)
    if args.questions:
        keep = {q.strip() for q in args.questions.split(",")}
        data = {k: v for k, v in data.items() if k in keep}
    d = jev_decider.get_decider()
    qs = jev_decider._questions()

    fitted: dict[str, list[str]] = {}
    print(f"== fit ({args.label_source} labels, levels {levels}) ==")
    for name, split in sorted(data.items()):
        tr = split["train"]
        n_yes = sum(y == 0 for _, y in tr)
        rare = min(n_yes, len(tr) - n_yes)
        if len(tr) < args.min_n or rare < args.min_class:
            print(f"  skip {name:<24} train n={len(tr)} yes={n_yes} (need n>={args.min_n}, rarer class>={args.min_class})")
            continue
        states, labels = [s for s, _ in tr], [y for _, y in tr]
        for lv in levels:
            t0 = time.time()
            try:
                art = d.calibrate(qs[name], states, labels) if lv == "L1" else d.fit_head(qs[name], states, labels)
            except ValueError as exc:
                print(f"  FAIL {name:<24} {lv}: {exc}")
                continue
            fitted.setdefault(name, []).append(lv)
            detail = (f"T={art['temperature']:.3f}" if lv == "L1" else
                      f"{art.get('method')} block {art.get('layer_abs')} oof_nll={art.get('cv', {}).get('oof_nll', float('nan')):.3f}")
            print(f"  fit  {name:<24} {lv} n={len(tr)} yes={n_yes}  {detail}  ({time.time() - t0:.0f}s)")

    if not fitted:
        print("nothing fitted; no artifact written")
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    d.save_artifacts(args.out)
    print(f"wrote {sum(map(len, fitted.values()))} artifact(s) -> {args.out}")

    if args.no_eval:
        return 0
    print("\n== evaluate on test split ==")
    report: dict = {"labels": args.labels, "label_source": args.label_source, "questions": {}}
    for name, lvls in sorted(fitted.items()):
        te = data[name]["test"]
        if not te:
            continue
        states = [s for s, _ in te]
        y = np.array([1 - lab for _, lab in te])        # 1 = Yes
        row = {}
        for lv in ["L0"] + lvls:
            t0 = time.time()
            decs = d.decide_batch(states, qs[name], level=lv)
            row[lv] = metrics(np.array([dec.p_true for dec in decs]), y)
            row[lv]["seconds_per_state"] = round((time.time() - t0) / len(states), 2)
        report["questions"][name] = row
        print(f"  {name:<24} test n={len(te)} yes={int(y.sum())}")
        for lv, m in row.items():
            print(f"      {lv}: acc={m['accuracy']:.3f}  ece={m['ece']:.3f}  brier={m['brier']:.3f}  "
                  f"mean_conf={m['mean_confidence']:.3f}  {m['seconds_per_state']}s/state")
    with open(args.out + ".report.json", "w") as f:
        json.dump(report, f, indent=1)
    print(f"report -> {args.out}.report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
