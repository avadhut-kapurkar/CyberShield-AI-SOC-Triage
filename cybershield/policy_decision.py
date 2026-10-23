"""Reusable policy-decision pattern for Strands Decider 2B.

To adapt: (1) define a PolicyQuestion with your options, (2) call
DeciderServerClient.decide(state, question), (3) branch on the result,
(4) optionally wrap the result in make_policy_gate() so a Strands agent's
tool calls are allowed/denied by the decision.
Requires a running server: strands-decider serve <model> --port 8099
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import requests


class DeciderResponseError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyQuestion:
    question_id: str
    instructions: str
    options: dict  # option name -> criteria text (the policy)

    def to_request(self, state: str) -> dict:
        return {
            "state": state,
            "questions": {
                self.question_id: {
                    "type": "choice",
                    "instructions": self.instructions,
                    "criteria": dict(self.options),
                }
            },
        }


SEVERITY_QUESTION = PolicyQuestion(
    question_id="severity",
    instructions="Apply the SOC alert triage policy. Which severity level applies to this security alert?",
    options={
        "LOW": "Informational or low-risk activity that is routine, expected, or authorized.",
        "MEDIUM": "Suspicious activity that requires investigation but shows no confirmed compromise.",
        "HIGH": "A potentially serious security incident (e.g. active compromise, ransomware, data theft) requiring urgent human review.",
    },
)


@dataclass
class PolicyDecision:
    option: str
    confidence: float
    confidence_source: str
    probabilities: dict
    source: str  # "STRANDS_DECIDER_2B" or "DEMO_MOCK"
    latency_ms: Optional[float] = None
    raw: Any = field(default=None, repr=False)

    @property
    def is_real(self) -> bool:
        return self.source == "STRANDS_DECIDER_2B"


def _find_probs(node: Any, options: dict) -> Optional[dict]:
    """Find a {option: probability} mapping anywhere inside the answer."""
    if isinstance(node, dict):
        if set(options).issubset(node) and all(isinstance(node[o], (int, float)) for o in options):
            return {o: float(node[o]) for o in options}
        for v in node.values():
            found = _find_probs(v, options)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _find_probs(v, options)
            if found:
                return found
    return None


def parse_choice_answer(answer: dict, options: dict) -> tuple:
    """Return (option, confidence, confidence_source, probabilities). Raises if unparseable."""
    probs = _find_probs(answer, options)
    if probs is None:
        raise DeciderResponseError(
            "Could not find per-option probabilities in the Decider response. "
            "Run scripts/probe_decider.py and adapt parse_choice_answer. Raw answer: "
            f"{str(answer)[:300]}"
        )
    top = max(probs, key=probs.get)
    n = len(options)
    reported = answer.get("confidence") if isinstance(answer, dict) else None
    if isinstance(reported, (int, float)):
        conf, src = float(reported), "reported by Decider server"
    else:
        conf = (probs[top] - 1 / n) / (1 - 1 / n)
        src = "derived from probabilities (documented rescaling: even split=0, certain=1)"
    return top, conf, src, probs


class DeciderServerClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8099", timeout: float = 120):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> dict:
        r = requests.get(f"{self.base_url}/health", timeout=10)
        r.raise_for_status()
        return r.json()

    def decide(self, state: str, question: PolicyQuestion) -> PolicyDecision:
        t0 = time.perf_counter()
        r = requests.post(f"{self.base_url}/v1/systemone", json=question.to_request(state), timeout=self.timeout)
        wall_ms = (time.perf_counter() - t0) * 1000
        r.raise_for_status()
        data = r.json()
        try:
            answer = data["answers"][question.question_id]
        except (KeyError, TypeError) as exc:
            raise DeciderResponseError(f"Unexpected response: {str(data)[:300]}") from exc
        option, conf, src, probs = parse_choice_answer(answer, question.options)
        return PolicyDecision(option, conf, src, probs, "STRANDS_DECIDER_2B", wall_ms, data)


class MockDecider:
    """DEMO/MOCK ONLY. Keyword rules. This is NOT Strands Decider 2B."""

    HIGH = ("ransom", ".locked", "mass file", "exfil", "mimikatz", "encodedcommand")
    MEDIUM = ("failed", "powershell", "scan", "suspicious", "unknown external")
    LOW_HINTS = ("successful login", "authorized", "routine")

    def decide(self, state: str, question: PolicyQuestion) -> PolicyDecision:
        s = state.lower()
        if any(k in s for k in self.HIGH):
            opt = "HIGH"
        elif any(k in s for k in self.LOW_HINTS) and "failed" not in s:
            opt = "LOW"
        elif any(k in s for k in self.MEDIUM):
            opt = "MEDIUM"
        else:
            opt = "LOW"
        probs = {o: (1.0 if o == opt else 0.0) for o in question.options}
        return PolicyDecision(opt, float("nan"), "n/a (mock has no confidence)", probs, "DEMO_MOCK")


def make_policy_gate(decision: PolicyDecision, allowed_options: set, tool_allowed_when: Callable = None):
    """Build a Strands InterventionHandler. Tools run only if the decision's option
    is in allowed_options; otherwise the call is denied. Wiring: Agent(interventions=[gate])."""
    from strands.interventions import Deny, InterventionHandler, Proceed

    class PolicyGate(InterventionHandler):
        name = "decider-policy-gate"

        def __init__(self):
            self.allowed_calls = 0
            self.denied_calls = 0

        def before_tool_call(self, event, **kwargs):
            if decision.option in allowed_options:
                self.allowed_calls += 1
                return Proceed()
            self.denied_calls += 1
            return Deny(reason=f"Policy decision is {decision.option}; this tool requires {sorted(allowed_options)}.")

    return PolicyGate()