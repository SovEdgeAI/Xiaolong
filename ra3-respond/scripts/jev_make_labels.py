#!/usr/bin/env python3
"""Generate supervision labels for the local decision model (jev_calibrate.py input).

1. Synthesize diverse incidents from the client/simulate.py scenarios: metrics
   scaled together over a wide range (0.1x–3x), severity/confidence varied, node ids
   shuffled, so labels cover more than the handful of canned alerts.
2. Label each incident with a teacher:
     --teacher llm   the existing function-calling engine (llm.py) with a strong
                     model (OPENAI_API_KEY / OPENAI_BASE_URL, --teacher-model).
     --teacher mock  the rule engine — only to exercise the pipeline; labels
                     then just encode the rules.
   With --votes K the teacher is asked K times and an action is labeled
   selected if a majority chose it; `agreement` records the vote fraction so
   unstable labels can be reviewed or dropped (--min-agreement).
3. Human review (recommended): edit a line's `reviewed_actions`; jev_calibrate.py
   uses it instead of `actions` when present.

Output: one JSON object per line
  {"id", "client_id", "attack_type", "severity", "confidence", "metadata",
   "actions": [...], "agreement": {action: fraction}, "label_source", "reviewed_actions": null}

Usage:
  python scripts/jev_make_labels.py --teacher llm --teacher-model gpt-5.5 -n 300 --votes 3 \\
      --out artifacts/labels.jsonl
  LLM_MODEL=anyjev python scripts/jev_calibrate.py --labels artifacts/labels.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import types
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "client"))
try:
    import httpx  # noqa: F401  (simulate.py imports it)
except ImportError:
    sys.modules["httpx"] = types.ModuleType("httpx")

from simulate import SCENARIOS  # noqa: E402

SEVERITIES = ["low", "medium", "high", "critical"]


def synth_incident(rng: random.Random, i: int) -> dict:
    attack = rng.choice(list(SCENARIOS))
    sc = rng.choice(SCENARIOS[attack])
    # one intensity factor per incident keeps related metrics consistent
    # (e.g. completed_handshakes stays below ports_probed); small per-metric noise
    scale = rng.uniform(0.1, 3.0)
    meta = {}
    for k, v in sc["metadata"].items():
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            meta[k] = v
        else:
            meta[k] = max(1, int(v * scale * rng.uniform(0.9, 1.1)))
    sev = sc["severity"] if rng.random() < 0.6 else rng.choice(SEVERITIES)
    conf = round(min(0.99, max(0.5, sc["confidence"] + rng.uniform(-0.2, 0.05))), 2)
    return {"id": f"lbl-{i:05d}", "client_id": f"bs_node_{rng.randint(1, 12):02d}",
            "attack_type": attack, "severity": sev, "confidence": conf, "metadata": meta}


def label(llm, inc: dict, votes: int) -> tuple[list[str], dict[str, float]]:
    counts: Counter = Counter()
    for _ in range(votes):
        d = llm.decide_actions(inc["id"], inc["client_id"], inc["attack_type"],
                               inc["severity"], inc["confidence"], inc["metadata"])
        counts.update({a["name"] for a in d["selected_actions"]})
    agreement = {n: round(c / votes, 3) for n, c in counts.items()}
    return sorted(n for n, f in agreement.items() if f > 0.5), agreement


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--teacher", choices=["llm", "mock"], required=True)
    ap.add_argument("--teacher-model", help="LLM_MODEL for --teacher llm (default: env LLM_MODEL)")
    ap.add_argument("-n", type=int, default=300, help="number of incidents")
    ap.add_argument("--votes", type=int, default=1, help="teacher calls per incident (majority vote)")
    ap.add_argument("--min-agreement", type=float, default=0.0,
                    help="drop incidents where any action's vote fraction is within (1-x, x)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(ROOT, "artifacts", "labels.jsonl"))
    args = ap.parse_args()

    if args.teacher == "mock":
        os.environ["LLM_MODEL"] = "mock"
    elif args.teacher_model:
        os.environ["LLM_MODEL"] = args.teacher_model
    if os.environ.get("LLM_MODEL", "").lower() == "anyjev":
        ap.error("the teacher must not be the model being calibrated (LLM_MODEL=anyjev)")
    import llm  # after LLM_MODEL is set: llm.MODEL is read at import

    rng = random.Random(args.seed)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    kept = dropped = failed = 0
    with open(args.out, "w") as f:
        for i in range(args.n):
            inc = synth_incident(rng, i)
            try:
                actions, agreement = label(llm, inc, args.votes)
            except llm.LLMError as exc:
                failed += 1
                print(f"  {inc['id']} teacher failed: {exc}", file=sys.stderr)
                continue
            if args.min_agreement and any(1 - args.min_agreement < a < args.min_agreement
                                          for a in agreement.values()):
                dropped += 1
                continue
            inc.update(actions=actions, agreement=agreement,
                       label_source=f"{args.teacher}:{llm.MODEL}x{args.votes}",
                       reviewed_actions=None)
            f.write(json.dumps(inc, ensure_ascii=False) + "\n")
            kept += 1
            print(f"  {inc['id']} {inc['attack_type']:<17} {inc['severity']:<8} → {', '.join(actions)}")
    print(f"wrote {kept} labeled incidents → {args.out}  (dropped {dropped}, failed {failed})")
    return 0 if kept else 1


if __name__ == "__main__":
    raise SystemExit(main())
