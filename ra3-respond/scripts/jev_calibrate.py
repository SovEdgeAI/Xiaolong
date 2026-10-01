#!/usr/bin/env python3
"""Fit AnyJev L1 artifacts (per-action temperature scaling) for the local decider.

Each candidate action is one yes/no question; this script collects labeled
incidents, reads the model's L0 probabilities for them, and fits one
temperature per question so that P(yes) becomes calibrated. The result is a
small JSON file; point JEV_ARTIFACTS at it and the decider serves those
questions at L1.

Label sources:
  --labels FILE.jsonl   one incident per line:
                          {"client_id", "attack_type", "severity", "confidence",
                           "metadata", "actions": ["enable_syn_cookie", ...]}
                        produced by scripts/jev_make_labels.py (stronger LLM as
                        teacher), or exported from the `responses` table.
                        `reviewed_actions`, when set, overrides `actions`.
  --from-mock N         N jittered incidents from client/simulate.py, labeled by
                        the rule engine (llm._mock_decide). Quick start only:
                        it calibrates toward the rules, not beyond them.

Usage:
  LLM_MODEL=anyjev python scripts/jev_calibrate.py --from-mock 80 --out artifacts/jev_l1.json
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "client"))
try:
    import httpx  # noqa: F401  (simulate.py imports it; huggingface_hub needs the real one)
except ImportError:
    sys.modules["httpx"] = types.ModuleType("httpx")

import jev_decider  # noqa: E402
import llm  # noqa: E402
from simulate import SCENARIOS  # noqa: E402


def mock_incidents(n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    severities = ["low", "medium", "high", "critical"]
    out = []
    for i in range(n):
        attack = rng.choice(list(SCENARIOS))
        sc = rng.choice(SCENARIOS[attack])
        meta = {k: (int(v * rng.uniform(0.3, 1.7)) if isinstance(v, (int, float)) else v)
                for k, v in sc["metadata"].items()}
        sev = sc["severity"] if rng.random() < 0.7 else rng.choice(severities)
        inc = {"client_id": sc["client_id"], "attack_type": attack, "severity": sev,
               "confidence": sc["confidence"], "metadata": meta}
        d = llm._mock_decide(f"cal-{i}", inc["client_id"], attack, sev, inc["confidence"], meta)
        inc["actions"] = [a["name"] for a in d["selected_actions"]]
        out.append(inc)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--labels", help="JSONL of labeled incidents")
    src.add_argument("--from-mock", type=int, metavar="N", help="generate N rule-labeled incidents")
    ap.add_argument("--out", default=os.path.join(ROOT, "artifacts", "jev_l1.json"))
    ap.add_argument("--min-n", type=int, default=20, help="min labeled incidents per question")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if args.labels:
        with open(args.labels) as f:
            incidents = [json.loads(line) for line in f if line.strip()]
    else:
        incidents = mock_incidents(args.from_mock, args.seed)
    print(f"{len(incidents)} labeled incidents")

    # question name -> (states, labels); noul labels: 0 = Yes, 1 = No
    per_q: dict[str, tuple[list, list]] = {}
    for inc in incidents:
        # a human correction (jev_make_labels.py output) overrides the teacher
        target = inc.get("reviewed_actions") or inc["actions"]
        state = jev_decider.incident_state(inc["client_id"], inc["attack_type"], inc["severity"],
                                           inc["confidence"], inc["metadata"])
        for name in jev_decider.candidate_actions(inc["attack_type"], inc["severity"]):
            states, labels = per_q.setdefault(name, ([], []))
            states.append(state)
            labels.append(0 if name in target else 1)

    d = jev_decider.get_decider()
    qs = jev_decider._questions()
    fitted = 0
    for name, (states, labels) in sorted(per_q.items()):
        n_yes = labels.count(0)
        if len(labels) < args.min_n or n_yes in (0, len(labels)):
            print(f"  skip {name:<24} n={len(labels)} yes={n_yes} (too few or single-class)")
            continue
        art = d.calibrate(qs[name], states, labels)
        fitted += 1
        print(f"  fit  {name:<24} n={len(labels)} yes={n_yes} T={art['temperature']:.3f}")

    if not fitted:
        print("nothing fitted; no artifact written")
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    d.save_artifacts(args.out)
    print(f"wrote {fitted} L1 artifact(s) → {args.out}  (serve with JEV_ARTIFACTS={args.out})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
