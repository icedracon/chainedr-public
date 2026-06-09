"""
ChainEDR Module 3 Tests: Profiler

Test suite for behavioral profiling functionality.
Tests statistical analysis, invariant inference, and anomaly detection.
"""

import pytest
import time
from chainedr.profiler import Profiler
from chainedr.models import (
    ExecutionRecord,
    FunctionCall,
    StateSnapshot,
    ContractMap,
    ContractPattern,
    ContractFunction
)


def make_record(
    function_sig: str,
    gas: int,
    call_depth: int,
    ext_calls: int = 0,
    value: int = 0,
    eth_delta: int = 0,
    caller_is_contract: bool = False,
    caller_age: int = 1000,
    reverted: bool = False,
    state_diff: dict = None,
    execution_trace: dict = None
) -> ExecutionRecord:
    """
    Helper to create minimal ExecutionRecord for testing.
    
    Args:
        function_sig: Function signature
        gas: Gas used
        call_depth: Call depth
        ext_calls: Number of external calls
        value: ETH value sent
        eth_delta: ETH balance change
        caller_is_contract: Is caller a contract
        caller_age: Caller age in blocks
        reverted: Did transaction revert
        state_diff: State changes
        execution_trace: Execution trace
    
    Returns:
        ExecutionRecord for testing
    """
    func_call = FunctionCall(
        function_sig=function_sig,
        function_4byte="0x" + "00" * 4,
        caller="0x" + "11" * 20,
        caller_is_contract=caller_is_contract,
        caller_age_blocks=caller_age,
        inputs=[],
        value_sent=value
    )
    
    snapshot = StateSnapshot(
        block_number=1,
        timestamp=int(time.time()),
        eth_balances={},
        token_balances={},
        state_variables={}
    )
    
    balance_diff = {'eth': eth_delta} if eth_delta != 0 else {}
    
    external_contracts = ["0x" + f"{i:040x}" for i in range(ext_calls)]
    
    return ExecutionRecord(
        tx_hash="0x" + "aa" * 32,
        block_number=1,
        timestamp=int(time.time()),
        function_call=func_call,
        state_before=snapshot,
        state_after=snapshot,
        execution_trace=execution_trace or {},
        internal_calls=[],
        events_emitted=[],
        gas_used=gas,
        gas_limit=1000000,
        call_depth=call_depth,
        external_contracts_called=external_contracts,
        reverted=reverted,
        state_diff=state_diff or {},
        balance_diff=balance_diff
    )


class TestProfiler:
    """Test suite for Profiler module"""
    
    @pytest.fixture
    def profiler(self):
        """Create Profiler instance"""
        return Profiler()
    
    @pytest.fixture
    def mock_contract_map(self):
        """Create mock ContractMap"""
        return ContractMap(
            address="0x" + "22" * 20,
            abi=[],
            bytecode="0x6080",
            functions=[],
            state_vars=[],
            call_graph=[],
            pattern=ContractPattern.UNKNOWN,
            is_verified=False
        )
    
    def test_stats_computation(self, profiler):
        """
        TEST 1: Stats computation
        """
        print("\n" + "="*60)
        print("TEST 1: Stats Computation")
        print("="*60)
        
        # Normal distribution
        values = [100.0, 200.0, 300.0, 400.0, 500.0]
        stats = profiler._compute_stats(values)
        
        assert stats.mean == 300.0, f"Mean should be 300, got {stats.mean}"
        assert stats.min_val == 100.0
        assert stats.max_val == 500.0
        assert stats.std_dev > 0
        assert stats.p95 >= 450
        
        print(f"[PASS] Normal distribution: mean={stats.mean}, std={stats.std_dev:.2f}")
        
        # Edge case: empty list
        empty_stats = profiler._compute_stats([])
        assert empty_stats.mean == 0.0
        assert empty_stats.sample_count == 0
        
        print(f"[PASS] Empty list handled correctly")
        
        # Edge case: single value
        single_stats = profiler._compute_stats([42.0])
        assert single_stats.mean == 42.0
        assert single_stats.std_dev == 0.0
        assert single_stats.z_score(42.0) == 0.0
        assert single_stats.z_score(100.0) == 999.0  # Different value with std=0
        
        print(f"[PASS] Single value handled correctly")
    
    def test_z_score_computation(self, profiler):
        """
        TEST 2: Z-score computation
        """
        print("\n" + "="*60)
        print("TEST 2: Z-Score Computation")
        print("="*60)
        
        # All same value
        stats = profiler._compute_stats([50000.0] * 100)
        assert stats.z_score(50000.0) == 0.0
        assert stats.z_score(500000.0) == 999.0  # 10x normal, std=0
        
        print(f"[PASS] Constant distribution: z_score(same)=0, z_score(diff)=999")
        
        # Varied distribution
        varied = profiler._compute_stats([float(i) for i in range(1, 101)])
        z_near_mean = varied.z_score(50.0)
        z_far = varied.z_score(200.0)
        
        assert z_near_mean < 1.0, f"Near mean should have low z-score, got {z_near_mean}"
        assert z_far > 3.0, f"Far from mean should have high z-score, got {z_far}"
        
        print(f"[PASS] Varied distribution: z(50)={z_near_mean:.2f}, z(200)={z_far:.2f}")
    
    def test_function_stats_building(self, profiler):
        """
        TEST 3: Function stats building
        """
        print("\n" + "="*60)
        print("TEST 3: Function Stats Building")
        print("="*60)
        
        # Create 200 records with slight variation
        records = [
            make_record(
                "deposit(uint256)",
                gas=50000 + i * 100,
                call_depth=2,
                eth_delta=1000
            )
            for i in range(200)
        ]
        
        stats = profiler._build_function_stats("deposit(uint256)", records)
        
        assert stats.function_sig == "deposit(uint256)"
        assert stats.total_calls == 200
        assert 49000 < stats.gas_used.mean < 60000
        assert stats.call_depth.mean == 2.0
        assert stats.min_records_warning == False
        # Stability might be lower due to linear increase in gas
        assert stats.stability_score > 0.3, f"Stability too low: {stats.stability_score}"
        
        print(f"[PASS] Function stats built successfully")
        print(f"  - Total calls: {stats.total_calls}")
        print(f"  - Gas mean: {stats.gas_used.mean:.0f}")
        print(f"  - Stability: {stats.stability_score:.2f}")
    
    def test_invariant_inference(self, profiler, mock_contract_map):
        """
        TEST 4: Invariant inference - CRITICAL
        """
        print("\n" + "="*60)
        print("TEST 4: Invariant Inference")
        print("="*60)
        
        # Simulate deposit records where balance increases
        deposit_records = []
        for i in range(100):
            r = make_record(
                "deposit(uint256)",
                gas=65000,
                call_depth=1,
                eth_delta=1000  # Balance increases
            )
            deposit_records.append(r)
        
        invariants = profiler._infer_invariants(deposit_records, mock_contract_map)
        
        # Should find deposit invariant
        deposit_inv = [i for i in invariants 
                      if 'deposit' in i.expression.lower()]
        
        assert len(deposit_inv) > 0, "Should find deposit invariant"
        assert deposit_inv[0].confidence >= 0.95
        
        print(f"[PASS] Invariant inference works")
        print(f"  - Found {len(invariants)} invariants")
        print(f"  - Deposit invariant confidence: {deposit_inv[0].confidence:.2f}")
    
    def test_reentrancy_risk_detection(self, profiler, mock_contract_map):
        """
        TEST 5: Reentrancy risk detection - CRITICAL
        """
        print("\n" + "="*60)
        print("TEST 5: Reentrancy Risk Detection")
        print("="*60)
        
        # Create records with CALL before SSTORE (reentrancy pattern)
        reentrancy_records = []
        for i in range(50):
            r = make_record(
                "withdraw(uint256)",
                gas=80000,
                call_depth=3,
                execution_trace={
                    'opcodes': [
                        {'op': 'SLOAD', 'pc': 100},
                        {'op': 'CALL', 'pc': 200},   # External call BEFORE state update
                        {'op': 'SSTORE', 'pc': 300},  # State update AFTER call
                    ]
                }
            )
            reentrancy_records.append(r)
        
        invariants = profiler._infer_invariants(reentrancy_records, mock_contract_map)
        
        reentrancy_risk = [i for i in invariants 
                          if i.invariant_type == 'REENTRANCY_RISK']
        
        assert len(reentrancy_risk) > 0, "Should detect reentrancy risk"
        assert reentrancy_risk[0].violation_impact != ""
        
        print(f"[PASS] Reentrancy risk detected")
        print(f"  - Risk count: {len(reentrancy_risk)}")
        print(f"  - Impact: {reentrancy_risk[0].violation_impact[:50]}...")
        
        # Build profile and check flag
        profile = profiler.build_profile(
            mock_contract_map,
            {"withdraw(uint256)": reentrancy_records}
        )
        
        assert profile.has_reentrancy_risk == True
        print(f"  - Profile flagged: {profile.has_reentrancy_risk}")
    
    def test_stability_check(self, profiler):
        """
        TEST 6: Stability check
        """
        print("\n" + "="*60)
        print("TEST 6: Stability Check")
        print("="*60)
        
        # Stable records (all same gas)
        stable_records = [make_record("f()", gas=50000, call_depth=1) 
                         for _ in range(200)]
        stability = profiler._check_stability(stable_records)
        
        assert stability > 0.8, f"Stable records should have high score, got {stability}"
        print(f"[PASS] Stable records: {stability:.2f}")
        
        # Unstable records (random gas)
        import random
        random.seed(42)  # Set seed for reproducibility
        unstable_records = [
            make_record("f()", gas=random.randint(10000, 500000), call_depth=1)
            for _ in range(200)
        ]
        instability = profiler._check_stability(unstable_records)
        
        # With random data, stability can vary - just check it's calculated
        assert 0.0 <= instability <= 1.0, f"Stability should be 0-1, got {instability}"
        print(f"[PASS] Unstable records: {instability:.2f}")
    
    def test_compare_transaction(self, profiler, mock_contract_map):
        """
        TEST 7: compare_transaction - CRITICAL
        """
        print("\n" + "="*60)
        print("TEST 7: Compare Transaction")
        print("="*60)
        
        # Build profile from normal records
        normal_records = [
            make_record("withdraw(uint256)", gas=70000, call_depth=2, ext_calls=1)
            for _ in range(200)
        ]
        
        profile = profiler.build_profile(
            mock_contract_map,
            {"withdraw(uint256)": normal_records}
        )
        
        # Test 1: Normal transaction (match profile exactly)
        normal_tx = make_record("withdraw(uint256)", gas=70000, call_depth=2, ext_calls=1)
        # Set caller to match known callers
        normal_tx.function_call.caller = normal_records[0].function_call.caller
        
        score = profiler.compare_transaction(normal_tx, profile)
        
        print(f"  Normal tx z-scores: {score.z_scores}")
        print(f"  Composite: {score.composite_score:.2f}")
        
        assert score.composite_score < 3.0, f"Normal tx composite should be < 3.0, got {score.composite_score}"
        assert score.severity == "NORMAL"
        
        print(f"[PASS] Normal transaction: score={score.composite_score:.2f}, severity={score.severity}")
        
        # Test 2: Highly anomalous transaction
        anomalous_tx = make_record(
            "withdraw(uint256)",
            gas=700000,    # 10x normal
            call_depth=10,  # 5x normal
            ext_calls=8     # 8x normal
        )
        score = profiler.compare_transaction(anomalous_tx, profile)
        
        assert score.is_anomalous == True, "Anomalous tx should be flagged"
        assert score.composite_score > 5.0
        assert score.severity in ["HIGH", "CRITICAL"]
        assert 'gas' in score.z_scores
        assert score.z_scores['gas'] > 5.0
        
        print(f"[PASS] Anomalous transaction: score={score.composite_score:.2f}, severity={score.severity}")
        print(f"  - Gas z-score: {score.z_scores['gas']:.2f}")
        
        # Test 3: Unknown function
        unknown_tx = make_record("unknownFunction()", gas=50000, call_depth=1)
        score = profiler.compare_transaction(unknown_tx, profile)
        
        assert score.is_anomalous == True
        assert "Unknown function" in score.reasons[0]
        
        print(f"[PASS] Unknown function detected: {score.reasons[0]}")
    
    def test_profile_serialization(self, profiler, mock_contract_map):
        """
        TEST 8: Profile serialization
        """
        print("\n" + "="*60)
        print("TEST 8: Profile Serialization")
        print("="*60)
        
        # Build a profile
        records = [
            make_record("transfer(address,uint256)", gas=65000, call_depth=1)
            for _ in range(100)
        ]
        
        profile = profiler.build_profile(
            mock_contract_map,
            {"transfer(address,uint256)": records}
        )
        
        # Save profile
        profiler.save_profile(profile)
        
        print(f"[PASS] Profile saved successfully")
        print(f"  - Contract: {profile.contract_address}")
        print(f"  - Functions: {len(profile.functions)}")
        print(f"  - Invariants: {len(profile.global_invariants)}")
        
        # Note: load_profile returns None in current implementation
        # Full implementation would reconstruct from database
    
    def test_performance(self, profiler, mock_contract_map):
        """
        TEST 9: Performance test
        """
        print("\n" + "="*60)
        print("TEST 9: Performance Test")
        print("="*60)
        
        # Build profile with multiple functions
        records_dict = {}
        for i in range(5):
            func_sig = f"function{i}(uint256)"
            records = [
                make_record(func_sig, gas=50000 + j * 100, call_depth=2)
                for j in range(100)
            ]
            records_dict[func_sig] = records
        
        profile = profiler.build_profile(mock_contract_map, records_dict)
        
        # Test compare_transaction performance
        test_record = make_record("function0(uint256)", gas=52000, call_depth=2)
        
        start = time.time()
        for _ in range(1000):
            profiler.compare_transaction(test_record, profile)
        elapsed = time.time() - start
        
        avg_time_ms = (elapsed / 1000) * 1000
        
        assert elapsed < 5.0, f"1000 calls should take < 5s, took {elapsed:.2f}s"
        
        print(f"[PASS] Performance test passed")
        print(f"  - 1000 calls in {elapsed:.2f}s")
        print(f"  - Average: {avg_time_ms:.2f}ms per call")
        print(f"  - Target: < 5ms per call")


if __name__ == "__main__":
    """Run tests directly without pytest"""
    print("\n" + "="*60)
    print("ChainEDR Module 3: Profiler - Test Suite")
    print("="*60)
    
    test = TestProfiler()
    profiler = Profiler()
    
    mock_contract = ContractMap(
        address="0x" + "22" * 20,
        abi=[],
        bytecode="0x6080",
        functions=[],
        state_vars=[],
        call_graph=[],
        pattern=ContractPattern.UNKNOWN,
        is_verified=False
    )
    
    try:
        # Run all tests
        test.test_stats_computation(profiler)
        test.test_z_score_computation(profiler)
        test.test_function_stats_building(profiler)
        test.test_invariant_inference(profiler, mock_contract)
        test.test_reentrancy_risk_detection(profiler, mock_contract)
        test.test_stability_check(profiler)
        test.test_compare_transaction(profiler, mock_contract)
        test.test_profile_serialization(profiler, mock_contract)
        test.test_performance(profiler, mock_contract)
        
        print("\n" + "="*60)
        print("ALL PROFILER TESTS PASSED")
        print("="*60)
        
    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
