"""AnyJev decision engine: a local open-source LLM as a calibrated action picker.

Instead of free-form function calling, every candidate action becomes one
typed yes/no question (AnyJev `Question.noul`). The answer probability is read
straight from the model's next-token logits — no generation — and debiased by
asking in both phrasing orders (L0). If an L1 artifact (temperature scaling fit
on labeled incidents, see scripts/jev_calibrate.py) exists for a question, it is
applied on top.

    selected = {action : P(yes | incident) >= JEV_THRESHOLD}

so each alert gets 1..N actions depending on its metrics. Hard rules stay in
code, not in the model:

  * log_incident always, and last;
  * alert_operator always for high/critical (asked as a question otherwise);
  * at least one mitigation: if none clears the threshold, the most probable
    one is taken and flagged as low-confidence;
  * with JEV_RESTRICT_TO_CATALOG=true (default), only actions whose
    `applicable_threats` include the attack type are asked.

Numeric parameters come from metadata-proportional formulas (the same ones as
the mock engine), since logit readout is not meant for free numbers. After the
decision is fixed, the same model generates a short analysis of *why*, grounded
in the probabilities and metrics (JEV_EXPLAIN=true).

Environment:
    JEV_MODEL                 HF model id or local path  (Qwen/Qwen3-4B)
    JEV_DEVICE / JEV_DTYPE    cpu / bfloat16
    JEV_BATCH_SIZE            prompts per forward pass    (8)
    JEV_THREADS               torch CPU threads           (3/4 of cores)
    JEV_THRESHOLD             P(yes) needed to select     (0.5)
    JEV_PRIOR                 none | batch | content_free (none)
    JEV_ARTIFACTS             L1/L2 artifact JSON path    (unset -> L0 only)
    JEV_MAX_LEVEL             cap: L0 | L1 | L2           (L2)
    JEV_RESTRICT_TO_CATALOG   true | false                (true)
    JEV_EXPLAIN               true | false                (true)
    JEV_EXPLAIN_MAX_TOKENS    generation budget           (384)
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from typing import Any

from actions import ACTION_DEFINITIONS, ALL_THREATS

# The attack classes RA3 has a tuned deterministic policy for. Anything else is
# an "unknown" attack: still answered (the LLM picks from the whole catalog and
# a behaviour-based fallback applies), just without a hand-tuned policy.
KNOWN_THREATS = set(ALL_THREATS)

logger = logging.getLogger("ra3.jev")

# NB: `os.getenv(X) or default` everywhere: docker compose passes unset
# variables as empty strings.
MODEL_ID = os.getenv("JEV_MODEL") or "Qwen/Qwen3-4B"
DEVICE = os.getenv("JEV_DEVICE") or "cpu"
DTYPE = os.getenv("JEV_DTYPE") or "bfloat16"
BATCH_SIZE = int(os.getenv("JEV_BATCH_SIZE") or 8)
# Using every core makes CPU matmuls several times slower (thread contention on
# hybrid P/E-core CPUs: 14 threads decode ~8x slower than 10 on a Core Ultra 5).
THREADS = int(os.getenv("JEV_THREADS") or 0) or max(1, (os.cpu_count() or 4) * 3 // 4)
THRESHOLD = float(os.getenv("JEV_THRESHOLD") or 0.5)
PRIOR = os.getenv("JEV_PRIOR") or "none"
ARTIFACTS = os.getenv("JEV_ARTIFACTS", "")
# Highest level to serve even when better artifacts are loaded: L0 | L1 | L2.
MAX_LEVEL = (os.getenv("JEV_MAX_LEVEL") or "L2").upper()
EXPLAIN_MAX_TOKENS = int(os.getenv("JEV_EXPLAIN_MAX_TOKENS") or 384)


def _flag(name: str, default: str) -> bool:
    return (os.getenv(name) or default).strip().lower() in ("1", "true", "yes")


RESTRICT_TO_CATALOG = _flag("JEV_RESTRICT_TO_CATALOG", "true")
EXPLAIN = _flag("JEV_EXPLAIN", "true")

MANDATORY = ("alert_operator", "log_incident")
SUPPORT = ("share_threat_intel",)  # optional, but not a mitigation
# Volumetric floods where blocking a small set of sources is the decisive fix.
# Single-source DoS/flood attacks where blocking a small set of sources is the
# decisive fix (rate_limit/timeout alone are weak). Slowrate included: a slow
# connection-exhaustion attack from one source is stopped by blocking it.
VOLUMETRIC_FLOODS = ("SYN_Flood", "ICMP_Flood", "UDP_Flood", "HTTP_Flood", "Slowrate_DoS")
# The low-collateral mitigation that lets the server cope without cutting the
# source off. If one of these handles the attack, block_ip is held back.
# ICMP_Flood / UDP_Flood have no effective server-side option here (the P4 meter
# is byte-rate), so they have no targeted mitigation and escalate to block.
TARGETED_MITIGATION = {
    "SYN_Flood": "enable_syn_cookie",
    "HTTP_Flood": "enable_http_rate_limit",
    "Slowrate_DoS": "set_connection_timeout",
}
# Ways to cut the offending source off, most preferred first. quarantine_ue is
# the 5G-native cut-off (isolate the UE + bar the subscriber in the core) and is
# preferred over the blunt block_ip when both are available. Picking one of
# these supersedes a mere throttle.
CUTOFFS = ("quarantine_ue", "block_ip")
# Reconnaissance scans: low harm, do not block by default.
SCANS = ("SYN_Scan", "TCP_Connect_Scan", "UDP_Scan")
# A scan at or above this probe rate (pps) is aggressive enough to block.
SCAN_RATE_BLOCK = int(os.getenv("JEV_SCAN_RATE_BLOCK") or 2000)
# At or below this many attacking sources, block them; above, rate-limit instead.
BLOCK_SOURCE_MAX = int(os.getenv("JEV_BLOCK_SOURCE_MAX") or 20)

SYSTEM = (
    "You are the decision engine of RA3, the alarm-response control plane of a "
    "security system for 5G federated-learning networks. You will be given one "
    "incident and one question about a single response action. Every action has "
    "side effects (blocking legitimate users, dropping federated-learning traffic, "
    "operator fatigue), so an action is necessary only if it directly counters the "
    "reported attack mechanism; most incidents need only one to three actions. "
    "Judge from the attack type, severity, confidence and the concrete metrics. "
    "Reply with the answer label only: no words, no punctuation, no explanation."
)

_DEFS = {a["name"]: a for a in ACTION_DEFINITIONS}

# Question text must stay fixed: L1 artifacts are keyed by its hash.
QUESTIONS: dict[str, Any] = {}


def _questions() -> dict[str, Any]:
    if not QUESTIONS:
        from anyjev import Question

        for name, a in _DEFS.items():
            if name == "log_incident":
                continue
            # "necessary" + an explicit No condition: a plain "should X run?"
            # makes Qwen3-4B answer Yes to nearly every action on high severity.
            QUESTIONS[name] = Question.noul(
                f"Is the response action `{name}` necessary for this incident? "
                f"What it does: {a['description']} "
                "Answer Yes only if it directly counters this attack; answer No if it "
                "targets a different kind of attack or is not needed.",
                name=name,
            )
    return QUESTIONS


class JevError(RuntimeError):
    """Raised when the local model cannot be loaded or queried."""


# ---------------------------------------------------------------------------
# Model (loaded once, shared across requests; forward passes are serialized)
# ---------------------------------------------------------------------------
_decider = None
_l1_keys: set[str] = set()   # question keys with their own L1 (temperature) artifact
_l2_keys: set[str] = set()   # question keys with their own L2 head
_load_lock = threading.Lock()
_run_lock = threading.Lock()


def get_decider():
    global _decider
    if _decider is not None:
        return _decider
    with _load_lock:
        if _decider is None:
            if MAX_LEVEL not in ("L0", "L1", "L2"):
                raise JevError(f"JEV_MAX_LEVEL={MAX_LEVEL!r}: expected L0, L1 or L2")
            try:
                import torch
                from anyjev import Decider
                from anyjev.backends.hf import HFBackend

                if DEVICE == "cpu":
                    torch.set_num_threads(THREADS)
                t0 = time.time()
                backend = HFBackend(MODEL_ID, device=DEVICE, dtype=DTYPE, batch_size=BATCH_SIZE)
                d = Decider(backend, level="L0", prior=PRIOR, system=SYSTEM)
            except Exception as exc:  # noqa: BLE001
                raise JevError(f"cannot load {MODEL_ID}: {exc}") from exc
            if ARTIFACTS and os.path.exists(ARTIFACTS):
                d.load_artifacts(ARTIFACTS)
                with open(ARTIFACTS) as f:
                    arts = json.load(f)
                _l1_keys.update(arts.get("artifacts", {}))
                _l2_keys.update(arts.get("heads", {}))  # L2 needs anyjev >= 0.2
            elif ARTIFACTS:
                logger.warning("JEV_ARTIFACTS=%s not found — serving all questions at L0", ARTIFACTS)
            logger.info("AnyJev decider ready: %s on %s (%.1fs, %d L1 artifacts, %d L2 heads, "
                        "JEV_MAX_LEVEL=%s)", MODEL_ID, DEVICE, time.time() - t0, len(_l1_keys),
                        len(_l2_keys), MAX_LEVEL)
            _decider = d
    return _decider


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------
def candidate_actions(attack_type: str, severity: str) -> list[str]:
    """Actions asked as questions for this alert (mandatory ones are not asked).

    For a KNOWN attack type, JEV_RESTRICT_TO_CATALOG (default) narrows the
    candidates to the actions whose `applicable_threats` list that type. For an
    UNKNOWN attack type there is no catalog mapping to narrow by, so every
    non-mandatory action is offered and the model judges each one on the
    incident's own metrics -- that is how RA3 responds to an attack it has never
    seen using the actions it already has.
    """
    known = attack_type in KNOWN_THREATS
    names = []
    for name in _questions():
        if name == "alert_operator" and severity in ("high", "critical"):
            continue  # forced by rule
        applicable = _DEFS[name]["_meta"]["applicable_threats"]
        if RESTRICT_TO_CATALOG and known and attack_type not in applicable:
            continue
        names.append(name)
    return names


def incident_state(client_id: str, attack_type: str, severity: str,
                   confidence: float, metadata: dict[str, Any]) -> dict[str, Any]:
    return {"client_id": client_id, "attack_type": attack_type, "severity": severity,
            "detector_confidence": confidence, "metadata": metadata}


def level_for(question) -> str:
    """The best level this question has its *own* artifact for.

    Never level="auto": every question here is a Yes/No noul, and anyjev routes a
    question without a head to any other head with the same kind and options —
    i.e. another action's head would silently answer it."""
    if question.key in _l2_keys and MAX_LEVEL == "L2":
        return "L2"
    if question.key in _l1_keys and MAX_LEVEL in ("L1", "L2"):
        return "L1"
    return "L0"


def score_actions(state: dict[str, Any], names: list[str]) -> dict[str, dict[str, Any]]:
    """P(yes) per action, each question read at the best level it has an artifact for."""
    d = get_decider()
    qs = _questions()
    groups: dict[str, list] = {}
    for n in names:
        groups.setdefault(level_for(qs[n]), []).append(qs[n])
    out: dict[str, dict[str, Any]] = {}
    for level, group in groups.items():
        for dec in d.decide(state, group, level=level):
            if dec.diagnostics.get("routed_from"):
                raise JevError(f"{dec.question.name}: served by another question's head "
                               f"({dec.diagnostics['routed_from']})")
            p_yes, p_no = (max(float(x), 1e-300) for x in dec.probs)
            out[dec.question.name] = {
                "p_yes": round(dec.p_true, 4),
                # unsaturated certainty: at L0 many p_yes round to 1.0, the margin
                # still differs (e.g. +27.6 vs +26.4) and gives a stable ordering
                "log_odds": round(math.log(p_yes) - math.log(p_no), 3),
                "level": dec.level,
                # probability mass the model put on Yes/No at all (L0/L1 only)
                "answer_mass": dec.diagnostics.get("answer_mass"),
                "order_flip": dec.diagnostics.get("order_flip_l0"),
            }
    return out


def _arguments(name: str, incident_id: str, client_id: str, attack_type: str,
               severity: str, confidence: float, metadata: dict[str, Any]) -> tuple[dict, str]:
    """Metadata-proportional parameters (same formulas as llm._mock_decide)."""
    m = metadata
    if name == "enable_syn_cookie":
        half_open = int(m.get("half_open_connections", 0))
        duration = 120 if half_open >= 40000 else 60
        return ({"client_id": client_id, "duration_minutes": duration},
                f"half_open_connections={half_open} -> {duration}m")
    if name == "rate_limit":
        proto = {"ICMP_Flood": "icmp", "UDP_Flood": "udp"}.get(attack_type, "tcp")
        rate = int(m.get("packet_rate") or m.get("echo_request_rate") or m.get("syn_rate") or 0)
        pps = max(1000, rate // 10) if rate else 5000
        return ({"client_id": client_id, "protocol": proto, "pps_limit": pps},
                f"observed rate={rate} -> cap {proto} at {pps} pps")
    if name == "enable_http_rate_limit":
        rpm = (int(m.get("request_rate", 6000)) // 10) or 600
        return ({"client_id": client_id, "requests_per_minute": rpm, "per_ip": True},
                f"request_rate={m.get('request_rate')} -> {rpm} req/min per IP")
    if name == "block_ip":
        if m.get("scanner_ip"):
            ips = [m["scanner_ip"]]
        elif isinstance(m.get("source_ip_list"), list):
            ips = list(m["source_ip_list"])
        else:
            srcs = int(m.get("unique_source_ips") or m.get("source_ips") or 1)
            ips = [f"192.0.2.{i}" for i in range(1, min(srcs, 20) + 1)]
        return ({"client_id": client_id, "ip_list": ips, "duration_minutes": 30},
                f"block {len(ips)} source IP(s) for 30m")
    if name == "throttle_ue_bandwidth":
        rate = int(m.get("packet_rate") or m.get("echo_request_rate")
                   or m.get("syn_rate") or m.get("request_rate") or 0)
        mbps = 2 if rate >= 2000 else 5          # heavier flood -> tighter cap
        return ({"client_id": client_id, "mbps": mbps, "duration_minutes": 30},
                f"observed rate={rate} -> cap UE at {mbps} Mbit/s")
    if name == "quarantine_ue":
        return ({"client_id": client_id, "duration_minutes": 30,
                 "reason": f"{attack_type} from this UE (severity {severity})"},
                "isolate at the switch + bar the subscriber in the core")
    if name == "set_connection_timeout":
        dur = float(m.get("avg_request_duration_s", 0))
        timeout = 10 if dur >= 300 else 15
        return ({"client_id": client_id, "timeout_seconds": timeout},
                f"avg_request_duration_s={dur:g} -> idle timeout {timeout}s")
    if name == "close_unnecessary_ports":
        return ({"client_id": client_id, "port_list": [23, 135, 445]},
                "close risky legacy ports 23/135/445")
    if name == "share_threat_intel":
        pattern = ", ".join(f"{k}={v}" for k, v in m.items())
        return ({"attack_type": attack_type, "source_pattern": pattern or attack_type,
                 "affected_nodes": [client_id]}, "broadcast signature to federation peers")
    if name == "alert_operator":
        return ({"incident_id": incident_id, "severity": severity,
                 "message": f"{attack_type} on {client_id} (confidence {confidence})",
                 "channel": "email"}, f"severity={severity}")
    raise KeyError(name)


# A flood is "overwhelming" when, even with the targeted mitigation, the sheer
# volume starves legitimate users on the shared path. Escalate to block then.
# Thresholds are deliberately high (near the server's saturation point).
SYN_OVERWHELM = int(os.getenv("JEV_SYN_OVERWHELM") or 500)       # half-open at ~backlog
HTTP_OVERWHELM = int(os.getenv("JEV_HTTP_OVERWHELM") or 100000)  # requests/min
SLOW_OVERWHELM = int(os.getenv("JEV_SLOW_OVERWHELM") or 150)     # held connections


def _num(m: dict, *keys: str) -> float:
    """First present numeric metadata value among keys, else 0."""
    for k in keys:
        v = m.get(k)
        if v not in (None, ""):
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


# Metadata keys that signal a reconnaissance scan vs. a volumetric/connection
# flood. Used to classify an UNKNOWN attack type by its behaviour.
_SCAN_KEYS = ("scanner_ip", "ports_probed", "scan_rate")
_FLOOD_KEYS = ("packet_rate", "echo_request_rate", "syn_rate", "request_rate",
               "bandwidth_mbps", "half_open_connections", "active_connections",
               "udp_rate", "pps")


def _looks_like_scan(metadata: dict) -> bool:
    return any(metadata.get(k) not in (None, "") for k in _SCAN_KEYS)


def _looks_like_flood(metadata: dict) -> bool:
    return any(_num(metadata, k) > 0 for k in _FLOOD_KEYS)


def _infer_targeted(metadata: dict) -> str | None:
    """Best server-side targeted mitigation for an UNKNOWN flood, from metrics.

    Mirrors the known-type TARGETED_MITIGATION map but keyed on the behaviour
    the metrics reveal (half-open table -> SYN cookies, request flood -> HTTP
    rate limit, held connections -> shorter timeout). None means "no targeted
    server-side option", which escalates like ICMP/UDP floods do.
    """
    m = metadata
    if _num(m, "half_open_connections", "syn_rate") > 0:
        return "enable_syn_cookie"
    if _num(m, "request_rate") > 0 or m.get("top_endpoint"):
        return "enable_http_rate_limit"
    if _num(m, "active_connections") > 0:
        return "set_connection_timeout"
    return None


def effective_class(attack_type: str, metadata: dict) -> tuple[str | None, str | None]:
    """(category, targeted_mitigation) for the graduated policy.

    category is "flood", "scan" or None. For a KNOWN attack type it comes from
    the tuned tables; for an UNKNOWN type it is inferred from the metrics so the
    same graduated response (prefer targeted mitigation, block only as a last
    resort) applies. None category means the attack could not be classified from
    its metadata -- the model's own selection and the mandatory rules stand.
    """
    if attack_type in VOLUMETRIC_FLOODS:
        return "flood", TARGETED_MITIGATION.get(attack_type)
    if attack_type in SCANS:
        return "scan", None
    # Unknown attack type: classify by behaviour. Scan signals win over flood
    # signals (a scan may incidentally carry a small packet rate).
    if _looks_like_scan(metadata):
        return "scan", None
    if _looks_like_flood(metadata):
        return "flood", _infer_targeted(metadata)
    return None, None


def _flood_overwhelming(attack_type: str, metadata: dict,
                        targeted: str | None = None) -> bool:
    m = metadata
    if attack_type == "SYN_Flood":
        return int(_num(m, "half_open_connections")) >= SYN_OVERWHELM
    if attack_type == "HTTP_Flood":
        return int(_num(m, "request_rate")) >= HTTP_OVERWHELM
    if attack_type == "Slowrate_DoS":
        return int(_num(m, "active_connections")) >= SLOW_OVERWHELM
    # Unknown flood: judge by the metric the inferred targeted mitigation treats.
    if targeted == "enable_syn_cookie":
        return int(_num(m, "half_open_connections")) >= SYN_OVERWHELM
    if targeted == "enable_http_rate_limit":
        return int(_num(m, "request_rate")) >= HTTP_OVERWHELM
    if targeted == "set_connection_timeout":
        return int(_num(m, "active_connections")) >= SLOW_OVERWHELM
    return False


def decide_actions(incident_id: str, client_id: str, attack_type: str, severity: str,
                   confidence: float, metadata: dict[str, Any]) -> dict[str, Any]:
    """Same contract as llm.decide_actions."""
    state = incident_state(client_id, attack_type, severity, confidence, metadata)
    names = candidate_actions(attack_type, severity)

    t0 = time.time()
    with _run_lock:
        try:
            scores = score_actions(state, names)
        except JevError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise JevError(f"AnyJev readout failed: {exc}") from exc
    decide_s = time.time() - t0

    chosen = {n for n, s in scores.items() if s["p_yes"] >= THRESHOLD}

    # --- Graduated response (deterministic) ----------------------------------
    # block_ip is a last resort: it cuts the source off entirely, which also
    # severs any legitimate traffic sharing that address. So prefer the targeted
    # mitigation that lets the server cope without cutting anyone off, and only
    # escalate to block_ip when that is not enough:
    #   * the flood is distributed across too many sources to mitigate per-flow
    #     by targeting (can't scrub here), OR
    #   * there is no effective targeted mitigation for this attack class, OR
    #   * the operator marks it already-mitigated-and-still-flooding
    #     (metadata.escalate = true).
    # Scans have no server-side mitigation, so they fall into "no targeted
    # option"; but a scan is low-harm, so block_ip is only for a persistent one.
    flood_policy = None
    held_back = set()   # actions the graduated policy deliberately removed
    category, targeted = effective_class(attack_type, metadata)
    unknown = attack_type not in KNOWN_THREATS
    # The preferred way to cut the source off: quarantine_ue if available, else
    # block_ip. Choosing it supersedes the blunter cut-off and any throttle.
    cutoff = next((c for c in CUTOFFS if c in names), None)

    def _apply_cutoff():
        chosen.add(cutoff)
        for other in CUTOFFS:
            if other != cutoff:
                chosen.discard(other)
        chosen.discard("rate_limit")
        chosen.discard("throttle_ue_bandwidth")   # a full cut-off supersedes a throttle

    def _hold_back_cutoff():
        for c in CUTOFFS:
            chosen.discard(c); held_back.add(c)

    if category == "flood" and cutoff:
        n_sources = int(metadata.get("unique_source_ips")
                        or metadata.get("source_ips") or 1)
        has_targeted = targeted in chosen if targeted else False
        # Severe floods overwhelm the shared path even with the targeted
        # mitigation (the server copes but legitimate users are still starved),
        # so escalate: keep the targeted action AND cut the few sources off.
        overwhelming = _flood_overwhelming(attack_type, metadata, targeted)
        escalate = bool(metadata.get("escalate")) or overwhelming
        distributed = n_sources > BLOCK_SOURCE_MAX

        if has_targeted and not escalate and not distributed:
            # targeted mitigation is in place and the source set is small:
            # let it do the work, do NOT cut the source off.
            _hold_back_cutoff()
            chosen.discard("rate_limit")           # ineffective byte-meter here
            flood_policy = (f"targeted ({targeted}) handles it; "
                            f"cut-off held back ({n_sources} src)")
        elif has_targeted and overwhelming and not distributed:
            # targeted + cut-off: the attack is too intense for the targeted
            # action alone to protect legitimate users; cut the few sources off.
            _apply_cutoff()
            flood_policy = f"severe {attack_type} -> {targeted} + {cutoff} ({n_sources} src)"
        elif distributed:
            # too many sources to cut off individually; best-effort rate limiting
            chosen.add("rate_limit")
            _hold_back_cutoff()
            flood_policy = f"distributed ({n_sources} sources) -> rate_limit, no cut-off"
        else:
            # no effective targeted option (or operator escalation): cut the
            # few identifiable sources off as the last resort.
            _apply_cutoff()
            why = "operator escalation" if escalate else \
                  ("no targeted mitigation" if not targeted else f"{targeted} not selected")
            flood_policy = f"{why} -> {cutoff} ({n_sources} src)"

    # Scans are reconnaissance, low immediate harm: reduce the attack surface
    # (close_unnecessary_ports) and log, but do NOT cut the source off by default
    # -- only a persistent/aggressive scan, or operator escalation, warrants it.
    elif category == "scan" and cutoff:
        escalate = bool(metadata.get("escalate"))
        aggressive = int(_num(metadata, "scan_rate")) >= SCAN_RATE_BLOCK
        if escalate or aggressive:
            _apply_cutoff()
            why = "operator escalation" if escalate else f"aggressive scan ({metadata.get('scan_rate')}/s)"
            flood_policy = f"{why} -> {cutoff}"
        else:
            _hold_back_cutoff()                    # just reduce surface + log
            flood_policy = "scan: reduce surface + log, cut-off held back"

    # Unknown attack type: make the behaviour-based classification auditable, and
    # if it could not be classified at all, fall back to the model's own
    # selection (never force block_ip on an attack RA3 cannot characterise).
    if unknown:
        if category is None:
            flood_policy = ("unknown attack, unclassifiable from metadata -> "
                            "model selection + alert/log only")
        else:
            flood_policy = f"unknown attack, inferred {category}: {flood_policy}"

    mitigations = [n for n in names if n not in MANDATORY and n not in SUPPORT]
    forced_mitigation = None
    # Fall back to the most likely mitigation ONLY among those the graduated
    # policy did not deliberately hold back (so a held-back block_ip is not
    # silently re-added here).
    fallback_pool = [n for n in mitigations if n not in held_back]
    if fallback_pool and not chosen.intersection(mitigations):
        forced_mitigation = max(fallback_pool, key=lambda n: scores[n]["log_odds"])
        chosen.add(forced_mitigation)

    # Order: mitigations by model certainty (log-odds; ties -> catalog order),
    # then support (share_threat_intel), then alert_operator, then log_incident.
    ordered = sorted((n for n in mitigations if n in chosen),
                     key=lambda n: (-scores[n]["log_odds"], mitigations.index(n)))
    ordered += [n for n in SUPPORT if n in chosen]
    if severity in ("high", "critical") or "alert_operator" in chosen:
        ordered.append("alert_operator")

    # ---- assemble actions + per-action decision records ------------------
    actions: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []   # structured explanation, one per selected action

    def add(name: str, args: dict, param_note: str) -> None:
        s = scores.get(name)
        if s is None:
            basis, conf, p_nec, lo, level = "mandatory_rule", 1.0, None, None, None
        else:
            basis = "model_low_confidence" if name == forced_mitigation else "model"
            conf, p_nec, lo, level = s["p_yes"], s["p_yes"], s["log_odds"], s["level"]
        actions.append({"name": name, "arguments": args, "confidence": conf, "reason": ""})
        records.append({"name": name, "decision_basis": basis, "confidence": conf,
                        "p_necessary": p_nec, "log_odds": lo, "calibration": level,
                        "arguments": args, "parameter_basis": param_note})

    for name in ordered:
        add(name, *_arguments(name, incident_id, client_id, attack_type,
                              severity, confidence, metadata))
    add("log_incident",
        {"incident_id": incident_id,
         "action_taken": ", ".join(a["name"] for a in actions) or "none",
         "notes": f"decided by AnyJev ({MODEL_ID})"},
        "every response is logged for audit")
    for i, (a, r) in enumerate(zip(actions, records), start=1):
        a["order"] = r["order"] = i

    rejected = [{"name": n, "decision_basis": "model", "confidence": round(1 - s["p_yes"], 4),
                 "p_necessary": s["p_yes"], "log_odds": s["log_odds"], "calibration": s["level"]}
                for n, s in sorted(scores.items(), key=lambda kv: -kv[1]["log_odds"])
                if n not in chosen]

    # ---- explanation: generated only after the decision is fixed ----------
    text, source, explain_s = None, "template", 0.0
    if EXPLAIN:
        t1 = time.time()
        try:
            with _run_lock:
                text = explain(state, records, rejected)
            source = "llm"
        except Exception:  # noqa: BLE001 — the decision stands without prose
            logger.exception("explanation generation failed; using template")
        explain_s = time.time() - t1
    text = text or {}
    rationales = text.get("rationales") or {}
    for r in records + rejected:
        r["rationale"] = str(rationales.get(r["name"]) or _template_rationale(r, severity))
    for a, r in zip(actions, records):
        a["reason"] = r["rationale"]
    overall = str(text.get("overall_assessment") or
                  f"{attack_type} ({severity}) on {client_id}: "
                  f"{len(actions)} action(s) selected by {MODEL_ID}.")

    explanation = {
        "engine": "anyjev",
        "model": MODEL_ID,
        "threshold": THRESHOLD,
        "incident": {"attack_type": attack_type, "severity": severity, "client_id": client_id},
        "overall_assessment": overall,
        "selected_actions": records,
        "rejected_actions": rejected,
        "explanation_source": source,
    }
    return {
        "selected_actions": actions,
        "llm_reasoning": overall,
        "explanation": explanation,
        "raw_llm_response": {
            "engine": "anyjev", "model": MODEL_ID, "threshold": THRESHOLD, "prior": PRIOR,
            "candidates": names, "scores": scores, "forced_mitigation": forced_mitigation,
            "flood_policy": flood_policy,
            "explanation": explanation,
            "decide_seconds": round(decide_s, 2), "explain_seconds": round(explain_s, 2),
        },
    }


def _template_rationale(r: dict[str, Any], severity: str) -> str:
    """Deterministic fallback when the model's explanation is unavailable."""
    if r["decision_basis"] == "mandatory_rule":
        if r["name"] == "log_incident":
            return "Mandatory: every response is logged for audit."
        return f"Mandatory for severity={severity}."
    p = r["p_necessary"]
    if "parameter_basis" not in r:  # a rejected candidate
        return f"Judged unnecessary for this incident (P(necessary)={p:.2f})."
    if r["decision_basis"] == "model_low_confidence":
        return (f"No mitigation reached the threshold; kept as the most likely one "
                f"(P(necessary)={p:.2f}); {r['parameter_basis']}.")
    return f"Judged necessary (P(necessary)={p:.2f}); {r['parameter_basis']}."


# ---------------------------------------------------------------------------
# Explanation (generation happens only after the decision is fixed)
# ---------------------------------------------------------------------------
_PREFILL = '{\n  "overall_assessment": "'


def explain(state: dict[str, Any], selected: list[dict[str, Any]],
            rejected: list[dict[str, Any]]) -> dict[str, Any]:
    """Ask the same model for English rationales, as JSON. Returns
    {"overall_assessment": str, "rationales": {action_name: str}}."""
    import torch

    backend = get_decider().backend
    tok, model = backend.tokenizer, backend.model

    def basis(r: dict[str, Any]) -> str:
        if r["p_necessary"] is None:
            return "mandatory rule"
        return f"P(necessary)={r['p_necessary']:.2f}"

    sel = "\n".join(f"- {r['name']} args={json.dumps(r['arguments'])} [{basis(r)}]"
                    for r in selected)
    rej = "\n".join(f"- {r['name']} [{basis(r)}]" for r in rejected) or "- (none)"
    names = [r["name"] for r in selected + rejected]
    skeleton = json.dumps({"overall_assessment": "...",
                           "rationales": {n: "..." for n in names}}, indent=2)
    user = (
        f"Incident:\n{json.dumps(state, indent=2)}\n\n"
        "The response decision is FINAL. A decision model scored, for each candidate "
        "action, the probability P(necessary) that it is necessary for this incident; "
        "actions are selected by that probability or by mandatory rules.\n"
        f"Selected actions:\n{sel}\n\nCandidate actions NOT selected:\n{rej}\n\n"
        "Explain this decision for the on-call operator, in English. Give one sentence "
        "per action (selected or not) saying why it was or was not chosen, citing "
        "concrete metric values from the incident, and a one-sentence overall "
        "assessment of the threat. Do not propose other actions or change the decision. "
        f"Reply with ONLY a JSON object of exactly this shape:\n{skeleton}"
    )
    messages = [{"role": "system", "content": "You are a senior 5G network security analyst."},
                {"role": "user", "content": user}]
    try:
        prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True,
                                         enable_thinking=False)
    except TypeError:
        prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    prompt += _PREFILL  # start the JSON for the model so it cannot drift into prose
    enc = tok(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=EXPLAIN_MAX_TOKENS, do_sample=False,
                             pad_token_id=tok.pad_token_id)
    raw = _PREFILL + tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True)
    return _parse_json(raw)


def _parse_json(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw[: raw.rfind("}") + 1])  # ignore trailing text after the object
    except json.JSONDecodeError:
        # truncated output: keep whatever complete fields precede the cut
        import re
        obj = {"rationales": dict(re.findall(r'"(\w+)"\s*:\s*"([^"]+)"', raw))}
        m = obj["rationales"].pop("overall_assessment", None)
        if m:
            obj["overall_assessment"] = m
    if not isinstance(obj, dict):
        raise ValueError("explanation is not a JSON object")
    return obj
