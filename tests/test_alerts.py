import pytest
from cybershield.alerts import AlertValidationError, SAMPLE_ALERTS, normalize_alert


def test_samples_are_valid():
    for a in SAMPLE_ALERTS.values():
        assert normalize_alert(**a).title


def test_empty_title_rejected():
    with pytest.raises(AlertValidationError):
        normalize_alert("", "something happened here")


def test_bad_ip_rejected():
    with pytest.raises(AlertValidationError):
        normalize_alert("t", "a long enough description", source_ip="999.1.1.1")


def test_control_chars_stripped_and_oversize_rejected():
    assert "\x00" not in normalize_alert("t\x00", "desc\x07 text here").to_state()
    with pytest.raises(AlertValidationError):
        normalize_alert("t", "x" * 5000)