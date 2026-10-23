import pytest
from cybershield.alerts import SAMPLE_ALERTS, normalize_alert
from cybershield.explainer import template_explanation
from cybershield.policy_decision import (DeciderResponseError, MockDecider, SEVERITY_QUESTION,
                                         parse_choice_answer)
from cybershield.workflow import triage

OPTS = SEVERITY_QUESTION.options


def test_request_has_typed_choice_with_all_options():
    req = SEVERITY_QUESTION.to_request("x")
    q = req["questions"]["severity"]
    assert q["type"] == "choice" and set(q["criteria"]) == {"LOW", "MEDIUM", "HIGH"}


def test_parse_with_reported_confidence():
    ans = {"type": "choice", "choice": "HIGH", "confidence": 0.8, "probabilities": {"LOW": 0.05, "MEDIUM": 0.1, "HIGH": 0.85}}
    opt, conf, src, probs = parse_choice_answer(ans, OPTS)
    assert opt == "HIGH" and conf == 0.8 and "reported" in src


def test_parse_derives_confidence_when_missing():
    ans = {"probs": {"LOW": 1 / 3, "MEDIUM": 1 / 3, "HIGH": 1 / 3 + 1e-9}}
    _, conf, src, _ = parse_choice_answer(ans, OPTS)
    assert conf == pytest.approx(0, abs=1e-6) and "derived" in src


def test_unparseable_raises_not_silent():
    with pytest.raises(DeciderResponseError):
        parse_choice_answer({"weird": 1}, OPTS)


def test_mock_is_labeled_and_never_real():
    d = MockDecider().decide("anything", SEVERITY_QUESTION)
    assert d.source == "DEMO_MOCK" and not d.is_real


@pytest.mark.parametrize("name,expected", [
    ("Possible ransomware indicator", "HIGH"),
    ("Routine successful login", "LOW"),
])
def test_mock_sample_alerts(name, expected):
    alert = normalize_alert(**SAMPLE_ALERTS[name])
    res = triage(alert, MockDecider(), lambda a, d: template_explanation(d), audit_path=None)
    assert res.decision.option == expected


def test_high_policy_action_recommends_human_and_no_destructive_steps():
    alert = normalize_alert(**SAMPLE_ALERTS["Possible ransomware indicator"])
    res = triage(alert, MockDecider(), lambda a, d: template_explanation(d), audit_path=None)
    assert "HUMAN ANALYST" in res.policy_action