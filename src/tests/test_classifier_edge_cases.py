"""
Additional edge case tests for Classifier module.
Tests scenarios that were previously untested.
"""

import pytest
from chainedr.classifier import Classifier
from chainedr.models import AnomalyAlert, FunctionCall, StateSnapshot
from chainedr.database import Database
from unittest.mock import Mock


@pytest.fixture
def classifier():
    """Create classifier with mock database"""
    mock_db = Mock(spec=Database)
    return Classifier(mock_db)


def test_classify_with_missing_required_fields(classifier):
    """Test that classifier raises ValueError for missing required fields"""
    # Missing tx_hash
    alert = AnomalyAlert(
        alert_id="test-1",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="",  # Empty
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=0,
        estimated_impact_usd=0
    )
    
    with pytest.raises(ValueError, match="tx_hash"):
        classifier.classify(alert)


def test_classify_with_none_dicts(classifier):
    """Test that classifier handles None dict fields gracefully"""
    alert = AnomalyAlert(
        alert_id="test-2",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores=None,  # None
        invariant_violations=[],
        reasons=[],
        eth_value=0,
        estimated_impact_usd=0,
        execution_trace=None,  # None
        balance_diff=None,  # None
        state_diff=None  # None
    )
    
    # Should not raise, should handle gracefully
    result = classifier.classify(alert)
    assert result is not None
    assert result.vulnerability_type == "UNCLASSIFIED_ANOMALY"


def test_signal_extraction_with_empty_external_calls(classifier):
    """Test signal extraction when external_contracts_called is empty"""
    alert = AnomalyAlert(
        alert_id="test-3",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=0,
        estimated_impact_usd=0,
        external_contracts_called=[]  # Empty
    )
    
    signals = classifier._extract_signals(alert)
    assert signals["has_flash_loan"] == False
    assert signals["many_external_calls"] == False


def test_signal_extraction_with_zero_caller_gain(classifier):
    """Test profit signal when caller gain is exactly 0"""
    alert = AnomalyAlert(
        alert_id="test-4",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=1000000000000000000,  # 1 ETH
        estimated_impact_usd=0,
        balance_diff={"0xaaa": 0}  # Exactly 0 gain
    )
    
    signals = classifier._extract_signals(alert)
    # 0 is not > 1.1 ETH, so should be False
    assert signals["profit_exceeds_input"] == False


def test_signal_extraction_with_negative_caller_gain(classifier):
    """Test profit signal when caller loses money (negative gain)"""
    alert = AnomalyAlert(
        alert_id="test-5",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=1000000000000000000,  # 1 ETH
        estimated_impact_usd=0,
        balance_diff={"0xaaa": -500000000000000000}  # Lost 0.5 ETH
    )
    
    signals = classifier._extract_signals(alert)
    # Negative gain should NOT be flagged as profit
    assert signals["profit_exceeds_input"] == False


def test_signal_extraction_with_large_profit(classifier):
    """Test profit signal when caller makes large profit"""
    alert = AnomalyAlert(
        alert_id="test-6",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=1000000000000000000,  # 1 ETH input
        estimated_impact_usd=0,
        balance_diff={"0xaaa": 5000000000000000000}  # Gained 5 ETH
    )
    
    signals = classifier._extract_signals(alert)
    # 5 ETH > 1.1 ETH, should be True
    assert signals["profit_exceeds_input"] == True


def test_recursive_call_detection_with_empty_trace(classifier):
    """Test recursive call detection with empty trace"""
    result = classifier._detect_recursive_call({})
    assert result == False


def test_recursive_call_detection_with_no_calls(classifier):
    """Test recursive call detection with trace that has no subcalls"""
    trace = {
        "from": "0xaaa",
        "to": "0xbbb"
        # No "calls" field
    }
    result = classifier._detect_recursive_call(trace)
    assert result == False


def test_recursive_call_detection_with_deep_recursion(classifier):
    """Test recursive call detection with multiple levels"""
    trace = {
        "from": "0xaaa",
        "to": "0xbbb",
        "calls": [
            {
                "from": "0xbbb",
                "to": "0xccc",
                "calls": [
                    {
                        "from": "0xccc",
                        "to": "0xaaa",  # Calls back to original
                        "calls": []
                    }
                ]
            }
        ]
    }
    result = classifier._detect_recursive_call(trace)
    assert result == True


def test_recursive_call_detection_with_self_call(classifier):
    """Test recursive call detection when contract calls itself"""
    trace = {
        "from": "0xaaa",
        "to": "0xbbb",
        "calls": [
            {
                "from": "0xbbb",
                "to": "0xbbb",  # Self-call
                "calls": []
            }
        ]
    }
    result = classifier._detect_recursive_call(trace)
    assert result == True


def test_classify_with_missing_z_score_keys(classifier):
    """Test classification when z_scores dict is missing expected keys"""
    alert = AnomalyAlert(
        alert_id="test-7",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},  # Empty dict, missing "call_depth" key
        invariant_violations=[],
        reasons=[],
        eth_value=0,
        estimated_impact_usd=0
    )
    
    signals = classifier._extract_signals(alert)
    # Should use .get() with default 0, so no KeyError
    assert signals["high_call_depth"] == False  # 0 > 3 is False


def test_flash_loan_detection_with_case_sensitivity(classifier):
    """Test that flash loan detection is case-insensitive"""
    alert = AnomalyAlert(
        alert_id="test-8",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabc",
        block_number=100,
        timestamp=1000,
        function_sig="test()",
        caller="0xaaa",
        anomaly_score=5.0,
        severity="HIGH",
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=0,
        estimated_impact_usd=0,
        external_contracts_called=[
            "0x87870BCA3F3FD6335C3F4CE8392D69350B4FA4E2"  # AAVE V3 in uppercase
        ]
    )
    
    signals = classifier._extract_signals(alert)
    # Should detect despite case difference
    assert signals["has_flash_loan"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
