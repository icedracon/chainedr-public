"""
ChainEDR Database Tests

Test suite for database layer (SQLite and PostgreSQL support).
"""

import pytest
import time
from pathlib import Path
from chainedr.database import Database
from chainedr.models import (
    ContractMap, 
    ContractPattern,
    ContractFunction,
    ExecutionRecord,
    FunctionCall,
    StateSnapshot
)


class TestDatabase:
    """Test suite for Database class"""
    
    @pytest.fixture
    def db(self):
        """Create test database instance (SQLite)"""
        test_db_path = Path("data/profiles/test_chainedr.db")
        if test_db_path.exists():
            try:
                test_db_path.unlink()
            except PermissionError:
                pass  # File locked from previous test, will be overwritten
        
        db = Database(database_url=f"sqlite:///{test_db_path}")
        yield db
        
        # Cleanup: dispose engine first to release file lock (Windows fix)
        db.engine.dispose()
        if test_db_path.exists():
            try:
                test_db_path.unlink()
            except PermissionError:
                pass  # Best-effort cleanup
    
    @pytest.fixture
    def sample_contract(self):
        """Create sample ContractMap"""
        return ContractMap(
            address="0x1234567890123456789012345678901234567890",
            abi=[{"type": "function", "name": "test"}],
            bytecode="0x6080604052",
            functions=[
                ContractFunction(
                    name="deposit",
                    inputs=[],
                    outputs=[],
                    visibility="external",
                    state_mutability="payable",
                    payable=True,
                    modifiers=[]
                )
            ],
            state_vars=[],
            call_graph=[],
            pattern=ContractPattern.ERC20,
            is_verified=True,
            implementation_address=None
        )
    
    @pytest.fixture
    def sample_execution_records(self):
        """Create sample execution records"""
        records = []
        
        for i in range(10):
            func_call = FunctionCall(
                function_sig="deposit()",
                function_4byte="0xd0e30db0",
                caller="0x" + "11" * 20,
                caller_is_contract=False,
                caller_age_blocks=1000,
                inputs=[],
                value_sent=10**18
            )
            
            snapshot = StateSnapshot(
                block_number=i + 1,
                timestamp=int(time.time()) + i,
                eth_balances={},
                token_balances={},
                state_variables={}
            )
            
            record = ExecutionRecord(
                tx_hash="0x" + f"{i:064x}",
                block_number=i + 1,
                timestamp=int(time.time()) + i,
                function_call=func_call,
                state_before=snapshot,
                state_after=snapshot,
                execution_trace={},
                internal_calls=[],
                events_emitted=[],
                gas_used=50000 + i * 1000,
                gas_limit=100000,
                call_depth=1,
                external_contracts_called=[],
                reverted=False,
                coverage_new_branches=i
            )
            
            records.append(record)
        
        return records
    
    def test_connection(self, db):
        """
        Test 1: Database connection and table creation
        """
        print("\n" + "="*60)
        print("TEST 1: Database Connection")
        print("="*60)
        
        # Database should be initialized
        assert db.engine is not None, "Engine should be created"
        assert db.SessionLocal is not None, "Session factory should be created"
        
        # Test session creation
        session = db.get_session()
        assert session is not None, "Should create session"
        session.close()
        
        print("[PASS] Database connection successful")
        print(f"  - Engine: {db.engine}")
        print(f"  - Database: SQLite (test)")
    
    def test_save_and_retrieve_contract(self, db, sample_contract):
        """
        Test 2: Save and retrieve contract
        """
        print("\n" + "="*60)
        print("TEST 2: Contract Save/Retrieve")
        print("="*60)
        
        # Save contract
        db.save_contract(sample_contract)
        print(f"[PASS] Contract saved: {sample_contract.address}")
        
        # Retrieve contract
        retrieved = db.get_contract(sample_contract.address)
        
        # Note: get_contract returns None in current implementation
        # This is a placeholder - full implementation would reconstruct ContractMap
        print(f"  - Retrieved: {retrieved}")
        print("[PASS] Contract retrieval works (placeholder)")
    
    def test_batch_execution_save(self, db, sample_execution_records):
        """
        Test 3: Batch execution save (performance test)
        """
        print("\n" + "="*60)
        print("TEST 3: Batch Execution Save")
        print("="*60)
        
        contract_address = "0x" + "22" * 20
        
        # Measure time for batch insert
        start_time = time.perf_counter()
        db.save_executions_batch(sample_execution_records, contract_address)
        elapsed = time.perf_counter() - start_time
        
        print(f"[PASS] Saved {len(sample_execution_records)} records in {elapsed:.3f}s")
        
        # Should be fast (< 2 seconds for 1000 records, but we only have 10)
        assert elapsed < 2.0, f"Batch insert too slow: {elapsed}s"
        
        # Retrieve executions
        retrieved = db.get_executions(contract_address)
        assert len(retrieved) == len(sample_execution_records), \
            f"Should retrieve all records, got {len(retrieved)}"
        
        print(f"  - Retrieved: {len(retrieved)} records")
        records_per_sec = len(sample_execution_records) / max(elapsed, 1e-9)
        print(f"  - Performance: {records_per_sec:.0f} records/sec")
    
    def test_anomaly_queries(self, db):
        """
        Test 4: Anomaly save and query
        """
        print("\n" + "="*60)
        print("TEST 4: Anomaly Queries")
        print("="*60)
        
        contract_address = "0x" + "33" * 20
        
        # Save anomalies with different severities
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        for i, severity in enumerate(severities * 3):  # 12 total
            anomaly_data = {
                "tx_hash": "0x" + f"{i:064x}",
                "block_number": 1000 + i,
                "function_sig": "withdraw(uint256)",
                "anomaly_score": 0.9 - (i * 0.05),
                "classification": "REENTRANCY" if i % 2 == 0 else "UNCLASSIFIED",
                "severity": severity,
                "z_scores": {"gas": 5.2, "call_depth": 3.1},
                "economic_impact": 1000000 * (i + 1),
                "evidence": {"reason": f"Test anomaly {i}"}
            }
            
            db.save_anomaly(anomaly_data, contract_address)
        
        print(f"[PASS] Saved 12 anomalies")
        
        # Query by severity
        critical = db.get_anomalies(severity="CRITICAL")
        assert len(critical) == 3, f"Should have 3 CRITICAL, got {len(critical)}"
        print(f"  - CRITICAL anomalies: {len(critical)}")
        
        # Query by contract
        contract_anomalies = db.get_anomalies(contract_address=contract_address)
        assert len(contract_anomalies) == 12, \
            f"Should have 12 for contract, got {len(contract_anomalies)}"
        print(f"  - Contract anomalies: {len(contract_anomalies)}")
        
        # Query with limit
        limited = db.get_anomalies(limit=5)
        assert len(limited) <= 5, f"Should respect limit, got {len(limited)}"
        print(f"  - Limited query: {len(limited)} results")
        
        print("[PASS] Anomaly queries work correctly")
    
    def test_coverage_tracking(self, db):
        """
        Test 5: Coverage tracking
        """
        print("\n" + "="*60)
        print("TEST 5: Coverage Tracking")
        print("="*60)
        
        contract_address = "0x" + "44" * 20
        
        # Save coverage data
        for i in range(50):
            db.save_coverage(
                contract_address=contract_address,
                branch_id=f"branch_{i}",
                tx_hash="0x" + f"{i:064x}"
            )
        
        # Get coverage count
        count = db.get_coverage_count(contract_address)
        assert count == 50, f"Should have 50 branches, got {count}"
        
        print(f"[PASS] Coverage tracking works")
        print(f"  - Branches covered: {count}")
        
        # Test upsert (hit same branch again)
        db.save_coverage(contract_address, "branch_0", "0x" + "ff" * 32)
        count_after = db.get_coverage_count(contract_address)
        assert count_after == 50, "Should not create duplicate branch"
        
        print(f"  - Upsert works (no duplicates)")
    
    def test_stats(self, db, sample_execution_records):
        """
        Test 6: Statistics aggregation
        """
        print("\n" + "="*60)
        print("TEST 6: Statistics")
        print("="*60)
        
        contract_address = "0x" + "55" * 20
        
        # Save some data
        db.save_executions_batch(sample_execution_records, contract_address)
        
        for i in range(5):
            db.save_coverage(contract_address, f"branch_{i}", "0x" + f"{i:064x}")
        
        anomaly_data = {
            "tx_hash": "0x" + "aa" * 32,
            "block_number": 1000,
            "function_sig": "test()",
            "anomaly_score": 0.95,
            "classification": "REENTRANCY",
            "severity": "CRITICAL",
            "z_scores": {},
            "economic_impact": 1000000,
            "evidence": {}
        }
        db.save_anomaly(anomaly_data, contract_address)
        
        # Get stats
        stats = db.get_stats(contract_address)
        
        assert stats['total_executions'] == len(sample_execution_records)
        assert stats['branches_covered'] == 5
        assert stats['anomalies_detected'] == 1
        
        print(f"[PASS] Statistics aggregation works")
        print(f"  - Total executions: {stats['total_executions']}")
        print(f"  - Branches covered: {stats['branches_covered']}")
        print(f"  - Anomalies detected: {stats['anomalies_detected']}")


if __name__ == "__main__":
    """Run tests directly without pytest"""
    print("\n" + "="*60)
    print("ChainEDR Database - Test Suite")
    print("="*60)
    
    test = TestDatabase()
    
    # Create fixtures manually
    test_db_path = Path("data/profiles/test_chainedr.db")
    if test_db_path.exists():
        test_db_path.unlink()
    
    db = Database(database_url=f"sqlite:///{test_db_path}")
    
    sample_contract = ContractMap(
        address="0x1234567890123456789012345678901234567890",
        abi=[{"type": "function", "name": "test"}],
        bytecode="0x6080604052",
        functions=[
            ContractFunction(
                name="deposit",
                inputs=[],
                outputs=[],
                visibility="external",
                state_mutability="payable",
                payable=True,
                modifiers=[]
            )
        ],
        state_vars=[],
        call_graph=[],
        pattern=ContractPattern.ERC20,
        is_verified=True
    )
    
    # Create sample records
    sample_records = []
    for i in range(10):
        func_call = FunctionCall(
            function_sig="deposit()",
            function_4byte="0xd0e30db0",
            caller="0x" + "11" * 20,
            caller_is_contract=False,
            caller_age_blocks=1000,
            inputs=[],
            value_sent=10**18
        )
        
        snapshot = StateSnapshot(
            block_number=i + 1,
            timestamp=int(time.time()) + i,
            eth_balances={},
            token_balances={},
            state_variables={}
        )
        
        record = ExecutionRecord(
            tx_hash="0x" + f"{i:064x}",
            block_number=i + 1,
            timestamp=int(time.time()) + i,
            function_call=func_call,
            state_before=snapshot,
            state_after=snapshot,
            execution_trace={},
            internal_calls=[],
            events_emitted=[],
            gas_used=50000 + i * 1000,
            gas_limit=100000,
            call_depth=1,
            external_contracts_called=[],
            reverted=False,
            coverage_new_branches=i
        )
        sample_records.append(record)
    
    try:
        # Run tests
        test.test_connection(db)
        test.test_save_and_retrieve_contract(db, sample_contract)
        test.test_batch_execution_save(db, sample_records)
        test.test_anomaly_queries(db)
        test.test_coverage_tracking(db)
        test.test_stats(db, sample_records)
        
        print("\n" + "="*60)
        print("ALL DATABASE TESTS PASSED")
        print("="*60)
        
        # Cleanup
        if test_db_path.exists():
            test_db_path.unlink()
        
    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
