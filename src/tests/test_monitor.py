"""
Tests for ChainEDR Runtime Monitor - Module 4

Tests two-level analysis system, pattern detection, and performance.
All tests use mocks - no real RPC calls.
"""

import pytest
import time
import json
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any

from chainedr.monitor import RuntimeMonitor, FLASH_LOAN_PROVIDERS
from chainedr.models import (
    MonitorConfig,
    BehavioralProfile,
    FunctionStats,
    StatsDistribution,
    AnomalyAlert
)
from chainedr.database import Database
from chainedr.profiler import Profiler


@pytest.fixture
def mock_db():
    """Mock database"""
    db = Mock(spec=Database)
    return db


@pytest.fixture
def mock_profiler():
    """Mock profiler with sample profile"""
    profiler = Mock(spec=Profiler)
    
    # Create sample profile
    profile = BehavioralProfile(
        contract_address="0x1234567890123456789012345678901234567890",
        contract_pattern="DEX",
        profiled_at_block=1000000,
        total_records_analyzed=100,
        functions={
            "swap(uint256,uint256)": FunctionStats(
                function_sig="swap(uint256,uint256)",
                total_calls=100,
                success_rate=0.98,
                gas_used=StatsDistribution(
                    min_val=50000,
                    max_val=150000,
                    mean=100000,
                    median=100000,
                    std_dev=10000,
                    p95=120000,
                    p99=130000,
                    sample_count=100
                ),
                call_depth=StatsDistribution(
                    min_val=1,
                    max_val=3,
                    mean=2,
                    median=2,
                    std_dev=0.5,
                    p95=3,
                    p99=3,
                    sample_count=100
                ),
                external_calls_count=StatsDistribution(
                    min_val=0,
                    max_val=2,
                    mean=1,
                    median=1,
                    std_dev=0.5,
                    p95=2,
                    p99=2,
                    sample_count=100
                ),
                internal_calls_count=StatsDistribution(
                    min_val=2,
                    max_val=10,
                    mean=5,
                    median=5,
                    std_dev=2,
                    p95=8,
                    p99=9,
                    sample_count=100
                ),
                value_sent=StatsDistribution(
                    min_val=0,
                    max_val=1000000000000000000,  # 1 ETH
                    mean=100000000000000000,  # 0.1 ETH
                    median=100000000000000000,
                    std_dev=50000000000000000,
                    p95=200000000000000000,
                    p99=500000000000000000,
                    sample_count=100
                ),
                eth_balance_delta=StatsDistribution(
                    min_val=-1000000000000000000,
                    max_val=1000000000000000000,
                    mean=0,
                    median=0,
                    std_dev=100000000000000000,
                    p95=200000000000000000,
                    p99=500000000000000000,
                    sample_count=100
                ),
                caller_age_blocks=StatsDistribution(
                    min_val=100,
                    max_val=1000000,
                    mean=50000,
                    median=50000,
                    std_dev=10000,
                    p95=70000,
                    p99=80000,
                    sample_count=100
                ),
                caller_is_contract_rate=0.1,
                known_callers=["0xabc", "0xdef"],
                unique_contracts_called=["0x111", "0x222"],
                typical_predecessors={},
                typical_successors={},
                state_change_frequency={},
                stability_score=0.9,
                min_records_warning=False
            )
        },
        global_invariants=[],
        overall_stability_score=0.9,
        has_reentrancy_risk=False,
        has_access_control_risk=False
    )
    
    profiler.load_profile.return_value = profile
    return profiler


@pytest.fixture
def monitor_config():
    """Monitor configuration"""
    return MonitorConfig(
        contract_addresses=["0x1234567890123456789012345678901234567890"],
        rpc_url="http://localhost:8545",
        archive_rpc_url="http://localhost:8545",
        fast_threshold=3.0,
        deep_threshold=5.0,
        fast_timeout_ms=100,
        deep_timeout_ms=10000,
        poll_interval_seconds=2.0,
        max_blocks_behind=50,
        eth_price_usd=3000.0
    )


@pytest.fixture
def mock_w3():
    """Mock Web3 instance"""
    w3 = MagicMock()
    
    # Mock block
    w3.eth.block_number = 1000000
    w3.eth.get_block.return_value = {
        "number": 1000000,
        "timestamp": 1700000000,
        "transactions": []
    }
    
    # Mock transaction
    w3.eth.get_transaction.return_value = {
        "hash": MagicMock(hex=lambda: "0xabc123"),
        "from": "0x9876543210987654321098765432109876543210",
        "to": "0x1234567890123456789012345678901234567890",
        "value": 100000000000000000,  # 0.1 ETH
        "input": "0x12345678",  # Function selector
        "blockNumber": 1000000
    }
    
    # Mock receipt
    w3.eth.get_transaction_receipt.return_value = {
        "transactionHash": "0xabc123",
        "blockNumber": 1000000,
        "gasUsed": 100000,
        "status": 1,
        "logs": []
    }
    
    # Mock get_code
    w3.eth.get_code.return_value = b""  # EOA
    
    # Mock provider for trace
    w3.provider.make_request.return_value = {
        "result": {
            "type": "CALL",
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": "0x0",
            "gas": "0x186a0",
            "gasUsed": "0x186a0",
            "input": "0x12345678",
            "output": "0x",
            "calls": []
        }
    }
    
    return w3


def test_profile_loading(mock_db, mock_profiler, monitor_config):
    """Test 1: Profile loading with warnings for missing/unstable"""
    monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
    
    # Mock Web3
    with patch('chainedr.monitor.Web3') as mock_web3_class:
        mock_web3_class.return_value = MagicMock()
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        
        # Load profiles
        monitor.load_profiles()
        
        # Verify profile loaded
        assert len(monitor.profiles) == 1
        assert "0x1234567890123456789012345678901234567890" in monitor.profiles
        
        # Test missing profile warning
        mock_profiler.load_profile.return_value = None
        monitor.profiles = {}
        monitor.load_profiles()
        assert len(monitor.profiles) == 0


def test_fast_analysis_normal(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 2: Fast analysis - normal tx → no alert"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Create normal transaction
        tx = {
            "hash": MagicMock(hex=lambda: "0xabc123"),
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": 100000000000000000,  # 0.1 ETH (normal)
            "input": "0xswap(uint256,uint256)",  # Known function
        }
        
        receipt = {
            "blockNumber": 1000000,
            "gasUsed": 100000,  # Normal gas
            "status": 1,
            "logs": []
        }
        
        profile = monitor.profiles["0x1234567890123456789012345678901234567890"]
        
        # Fast analyze
        alert = monitor._fast_analyze(tx, receipt, profile)
        
        # Should not generate alert (z-scores below threshold)
        assert alert is None


def test_fast_analysis_anomalous(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 3: Fast analysis - anomalous tx → alert generated"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Create anomalous transaction (very high gas)
        tx = {
            "hash": MagicMock(hex=lambda: "0xabc123"),
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": 100000000000000000,
            "input": "0xswap(uint256,uint256)",
        }
        
        receipt = {
            "blockNumber": 1000000,
            "gasUsed": 200000,  # 10σ above mean (100k ± 10k)
            "status": 1,
            "logs": []
        }
        
        profile = monitor.profiles["0x1234567890123456789012345678901234567890"]
        
        # Fast analyze
        alert = monitor._fast_analyze(tx, receipt, profile)
        
        # Should generate alert
        assert alert is not None
        assert alert.anomaly_score >= monitor_config.fast_threshold
        assert alert.analysis_mode == "FAST"
        assert len(alert.reasons) > 0


def test_deep_analysis_enrichment(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 4: Deep analysis - enriches alert with trace"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Create initial alert
        alert = AnomalyAlert(
            alert_id="test-123",
            contract_address="0x1234567890123456789012345678901234567890",
            tx_hash="0xabc123",
            block_number=1000000,
            timestamp=1700000000,
            function_sig="swap(uint256,uint256)",
            caller="0x9876543210987654321098765432109876543210",
            anomaly_score=6.0,
            severity="MEDIUM",
            z_scores={"gas": 6.0},
            invariant_violations=[],
            reasons=["GAS anomaly: 6.0σ from baseline"],
            eth_value=100000000000000000,
            estimated_impact_usd=300.0,
            detected_at=time.time(),
            analysis_time_ms=50.0,
            analysis_mode="FAST"
        )
        
        tx = {
            "hash": MagicMock(hex=lambda: "0xabc123"),
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": 100000000000000000,
            "input": "0xswap(uint256,uint256)",
        }
        
        receipt = {
            "blockNumber": 1000000,
            "gasUsed": 200000,
            "status": 1,
            "logs": []
        }
        
        # Deep analyze
        enriched_alert = monitor._deep_analyze(alert, tx, receipt)
        
        # Should be enriched
        assert enriched_alert.analysis_mode == "DEEP"
        assert enriched_alert.execution_trace is not None
        assert isinstance(enriched_alert.internal_calls, list)
        assert isinstance(enriched_alert.external_contracts_called, list)


def test_reentrancy_detection(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 5: Reentrancy pattern detection"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        
        # Create trace with reentrancy pattern
        # A calls B, B calls back to A
        trace = {
            "type": "CALL",
            "from": "0xaaa",
            "to": "0xbbb",
            "calls": [
                {
                    "type": "CALL",
                    "from": "0xbbb",
                    "to": "0xaaa",  # Reentrancy!
                    "calls": []
                }
            ]
        }
        
        # Should detect reentrancy
        assert monitor._check_reentrancy_pattern(trace) == True
        
        # Normal trace (no reentrancy)
        normal_trace = {
            "type": "CALL",
            "from": "0xaaa",
            "to": "0xbbb",
            "calls": [
                {
                    "type": "CALL",
                    "from": "0xbbb",
                    "to": "0xccc",
                    "calls": []
                }
            ]
        }
        
        assert monitor._check_reentrancy_pattern(normal_trace) == False


def test_flash_loan_detection(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 6: Flash loan detection"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        
        # Create trace with flash loan provider
        aave_address = list(FLASH_LOAN_PROVIDERS)[0]
        trace = {
            "type": "CALL",
            "from": "0xaaa",
            "to": aave_address,
            "calls": []
        }
        
        tx = {"from": "0xaaa"}
        
        # Should detect flash loan
        assert monitor._check_flash_loan_pattern(trace, tx) == True
        
        # Normal trace (no flash loan)
        normal_trace = {
            "type": "CALL",
            "from": "0xaaa",
            "to": "0xbbb",
            "calls": []
        }
        
        assert monitor._check_flash_loan_pattern(normal_trace, tx) == False


def test_block_processing(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 7: Block processing - filter only monitored contracts"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Mock block with multiple transactions
        mock_w3.eth.get_block.return_value = {
            "number": 1000000,
            "timestamp": 1700000000,
            "transactions": [
                {
                    "hash": MagicMock(hex=lambda: "0xabc123"),
                    "from": "0x9876543210987654321098765432109876543210",
                    "to": "0x1234567890123456789012345678901234567890",  # Monitored
                    "value": 100000000000000000,
                    "input": "0xswap(uint256,uint256)",
                },
                {
                    "hash": MagicMock(hex=lambda: "0xdef456"),
                    "from": "0x9876543210987654321098765432109876543210",
                    "to": "0x9999999999999999999999999999999999999999",  # Not monitored
                    "value": 100000000000000000,
                    "input": "0x12345678",
                }
            ]
        }
        
        # Process block
        alerts = monitor._process_block(1000000)
        
        # Should only process monitored contract
        assert monitor.stats.blocks_processed == 1
        assert monitor.stats.transactions_analyzed == 1  # Only 1 tx analyzed


def test_replay_blocks(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 8: Replay historical blocks"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Mock block with transaction
        mock_w3.eth.get_block.return_value = {
            "number": 1000000,
            "timestamp": 1700000000,
            "transactions": [
                {
                    "hash": MagicMock(hex=lambda: "0xabc123"),
                    "from": "0x9876543210987654321098765432109876543210",
                    "to": "0x1234567890123456789012345678901234567890",
                    "value": 100000000000000000,
                    "input": "0xswap(uint256,uint256)",
                }
            ]
        }
        
        # Replay blocks
        alerts = monitor.replay_blocks(1000000, 1000005)
        
        # Should process 6 blocks
        assert monitor.stats.blocks_processed == 6


def test_callback_system(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 9: Callback system - on_alert fires correctly"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        # Register callback
        alerts_received = []
        
        def callback(alert: AnomalyAlert):
            alerts_received.append(alert)
        
        monitor.on_alert(callback)
        
        # Create anomalous transaction
        tx = {
            "hash": MagicMock(hex=lambda: "0xabc123"),
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": 100000000000000000,
            "input": "0xswap(uint256,uint256)",
        }
        
        receipt = {
            "blockNumber": 1000000,
            "gasUsed": 200000,  # Anomalous
            "status": 1,
            "logs": []
        }
        
        # Process transaction
        monitor._process_transaction("0xabc123", "0x1234567890123456789012345678901234567890")
        
        # Callback should have been called
        assert len(alerts_received) > 0


def test_performance_100_txs(mock_db, mock_profiler, monitor_config, mock_w3):
    """Test 10: Performance - 100 txs < 1 second total"""
    with patch('chainedr.monitor.Web3', return_value=mock_w3):
        monitor = RuntimeMonitor(monitor_config, mock_db, mock_profiler)
        monitor.load_profiles()
        
        profile = monitor.profiles["0x1234567890123456789012345678901234567890"]
        
        # Create normal transaction
        tx = {
            "hash": MagicMock(hex=lambda: "0xabc123"),
            "from": "0x9876543210987654321098765432109876543210",
            "to": "0x1234567890123456789012345678901234567890",
            "value": 100000000000000000,
            "input": "0xswap(uint256,uint256)",
        }
        
        receipt = {
            "blockNumber": 1000000,
            "gasUsed": 100000,
            "status": 1,
            "logs": []
        }
        
        # Process 100 transactions
        start_time = time.time()
        
        for i in range(100):
            monitor._fast_analyze(tx, receipt, profile)
        
        elapsed = time.time() - start_time
        
        # Should complete in < 1 second
        assert elapsed < 1.0
        print(f"\n✓ Performance: 100 txs analyzed in {elapsed:.3f}s ({elapsed*10:.1f}ms avg)")


def test_integration_euler_attack():
    """Test 11: Integration test with Euler Finance attack trace"""
    # This test would use saved Euler attack trace
    # For now, we'll create a mock that simulates the attack pattern
    
    # Euler attack characteristics:
    # - Flash loan from AAVE
    # - Multiple reentrancy calls
    # - Large value transfers
    
    trace_file = "data/known_attacks/euler_attack_trace.json"
    
    # Mock the trace (in production, would load from file)
    euler_trace = {
        "type": "CALL",
        "from": "0xattacker",
        "to": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",  # AAVE V3
        "calls": [
            {
                "type": "CALL",
                "from": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
                "to": "0xeuler",
                "calls": [
                    {
                        "type": "CALL",
                        "from": "0xeuler",
                        "to": "0xattacker",  # Reentrancy
                        "calls": []
                    }
                ]
            }
        ]
    }
    
    # Create monitor
    config = MonitorConfig(
        contract_addresses=["0xeuler"],
        rpc_url="http://localhost:8545",
        archive_rpc_url="http://localhost:8545",
        fast_threshold=3.0,
        deep_threshold=5.0
    )
    
    mock_db = Mock(spec=Database)
    mock_profiler = Mock(spec=Profiler)
    
    with patch('chainedr.monitor.Web3') as mock_web3_class:
        mock_w3 = MagicMock()
        mock_web3_class.return_value = mock_w3
        
        monitor = RuntimeMonitor(config, mock_db, mock_profiler)
        
        # Check patterns
        assert monitor._check_flash_loan_pattern(euler_trace, {}) == True
        assert monitor._check_reentrancy_pattern(euler_trace) == True
        
        print("\n✓ Euler attack patterns detected: FLASH_LOAN + REENTRANCY")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
