"""
Tests for Module 7: Reporter

Comprehensive tests for all report generation functionality.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch

from chainedr.reporter import Reporter
from chainedr.models import (
    Report, ReportSection, ReportConfig,
    ClassifiedVulnerability, AnomalyAlert, ExploitResult,
    BehavioralProfile, AttackPattern, FunctionStats, StatsDistribution,
    Invariant, FunctionCall, StateSnapshot, ExecutionRecord
)
from chainedr.database import Database


@pytest.fixture
def mock_db():
    """Create mock database"""
    db = Mock(spec=Database)
    db.save_report = Mock()
    db.get_profile = Mock()
    db.get_alerts = Mock()
    db.get_classified_vulnerabilities = Mock()
    db.get_exploits = Mock()
    return db


@pytest.fixture
def reporter(mock_db):
    """Create Reporter instance"""
    return Reporter(mock_db)


@pytest.fixture
def sample_alert():
    """Create sample anomaly alert"""
    return AnomalyAlert(
        alert_id="alert-123",
        contract_address="0x1234567890123456789012345678901234567890",
        tx_hash="0xabcdef1234567890",
        block_number=19847293,
        timestamp=1713015600,
        function_sig="withdraw(uint256)",
        caller="0x9999999999999999999999999999999999999999",
        anomaly_score=8.5,
        severity="CRITICAL",
        z_scores={"gas": 5.2, "call_depth": 3.8, "value": 2.1},
        invariant_violations=["balance_check_failed"],
        reasons=[
            "Gas usage 5.2σ above normal",
            "Call depth 3.8σ above normal",
            "Invariant violation: balance_check_failed"
        ],
        eth_value=1000000000000000000,
        estimated_impact_usd=3000.0,
        external_contracts_called=["0x8888888888888888888888888888888888888888"],
        detected_at=1713015601.0,
        analysis_time_ms=50.0
    )


@pytest.fixture
def sample_classified_reentrancy(sample_alert):
    """Create sample classified reentrancy vulnerability"""
    attack_pattern = AttackPattern(
        pattern_id="reentrancy-001",
        name="Classic Reentrancy",
        description="Reentrancy attack pattern",
        indicators=["recursive_call", "state_change_after_call"],
        confidence=0.95,
        matched_signals=["recursive_call_detected", "balance_updated_late"]
    )
    
    return ClassifiedVulnerability(
        classification_id="class-123",
        alert=sample_alert,
        vulnerability_type="REENTRANCY",
        confidence=0.95,
        attack_pattern=attack_pattern,
        severity="CRITICAL",
        cvss_score=9.5,
        estimated_loss_usd=50000.0,
        affected_functions=["withdraw(uint256)", "transfer(address,uint256)"],
        attack_vector="External call before state update allows recursive withdrawal",
        fix_suggestion="Use checks-effects-interactions pattern or reentrancy guard",
        fix_code_snippet="modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }",
        similar_attacks=["DAO Hack 2016", "Lendf.me 2020"],
        cve_references=["CVE-2016-XXXX"],
        exploitability="HIGH",
        proof_of_concept_possible=True,
        detection_rule="title: Reentrancy Detection\ndetection:\n  - recursive_call: true\n  - state_change_after: true",
        ioc_list=["0x9999999999999999999999999999999999999999"]
    )


@pytest.fixture
def sample_unclassified(sample_alert):
    """Create sample unclassified vulnerability"""
    return ClassifiedVulnerability(
        classification_id="class-unclass-123",
        alert=sample_alert,
        vulnerability_type="UNCLASSIFIED",
        confidence=0.0,
        attack_pattern=None,
        severity="HIGH",
        cvss_score=7.0,
        estimated_loss_usd=10000.0,
        affected_functions=["withdraw(uint256)"],
        attack_vector="Unknown anomalous behavior",
        anomaly_description="Unusual gas pattern and call depth detected",
        research_notes="Requires manual investigation to determine root cause"
    )


@pytest.fixture
def sample_exploit(sample_classified_reentrancy):
    """Create sample exploit result"""
    exploit_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyAttacker {
    VulnerableContract target;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}"""
    
    return ExploitResult(
        exploit_id="exploit-123",
        vulnerability=sample_classified_reentrancy,
        status="SUCCESS",
        foundry_test_code=exploit_code,
        foundry_test_path="test/exploits/Exploit_Reentrancy_123.t.sol",
        executed=True,
        profit_wei=5000000000000000000,
        profit_usd=15000.0,
        gas_cost_wei=500000000000000,
        net_profit_wei=4500000000000000000,
        execution_output="Test passed. Profit: 5 ETH",
        attack_tx_sequence=["0xabc123", "0xdef456"],
        vulnerable_function="withdraw(uint256)",
        exploit_contract_code=exploit_code
    )


@pytest.fixture
def sample_profile():
    """Create sample behavioral profile"""
    func_stats = FunctionStats(
        function_sig="withdraw(uint256)",
        total_calls=100,
        success_rate=0.98,
        gas_used=StatsDistribution(50000, 150000, 80000, 78000, 15000, 110000, 130000, 100),
        call_depth=StatsDistribution(1, 5, 2, 2, 1, 4, 5, 100),
        external_calls_count=StatsDistribution(0, 3, 1, 1, 0.5, 2, 3, 100),
        internal_calls_count=StatsDistribution(0, 10, 3, 3, 2, 8, 10, 100),
        value_sent=StatsDistribution(0, 1e18, 0.5e18, 0.4e18, 0.3e18, 0.9e18, 1e18, 100),
        eth_balance_delta=StatsDistribution(-1e18, 1e18, 0, 0, 0.5e18, 0.8e18, 1e18, 100),
        caller_age_blocks=StatsDistribution(0, 1000000, 50000, 40000, 30000, 80000, 100000, 100),
        caller_is_contract_rate=0.3,
        known_callers=["0xaaaa", "0xbbbb"],
        unique_contracts_called=["0xcccc"],
        typical_predecessors={"deposit(uint256)": 0.5},
        typical_successors={"balanceOf(address)": 0.3},
        state_change_frequency={"balance": 0.95},
        stability_score=0.85
    )
    
    invariant = Invariant(
        invariant_id="inv-001",
        expression="balance[caller] <= totalSupply",
        invariant_type="ECONOMIC",
        confidence=1.0,
        support_count=100,
        total_checked=100,
        violation_count=0,
        auto_inferred=True,
        confirmed=True,
        violation_impact="Balance exceeds total supply"
    )
    
    return BehavioralProfile(
        contract_address="0x1234567890123456789012345678901234567890",
        contract_pattern="LENDING",
        profiled_at_block=19847000,
        total_records_analyzed=500,
        functions={"withdraw(uint256)": func_stats},
        global_invariants=[invariant],
        overall_stability_score=0.85,
        has_reentrancy_risk=True,
        has_access_control_risk=False
    )


# TEST 1: Bug bounty report generation
def test_bug_bounty_report_generation(reporter, sample_classified_reentrancy, sample_exploit):
    """Test bug bounty report generation with exploit"""
    report = reporter.generate_bug_bounty_report(sample_classified_reentrancy, sample_exploit)
    
    assert report.report_type == "BUG_BOUNTY"
    assert report.critical_count == 1
    assert report.high_count == 0
    assert "REENTRANCY" in report.title or "Reentrancy" in report.title
    
    # Check required sections present
    section_titles = [s.title for s in report.sections]
    assert "Summary" in section_titles
    assert "Vulnerability Details" in section_titles
    assert "Impact" in section_titles
    assert "Proof of Concept" in section_titles
    assert "Root Cause Analysis" in section_titles
    assert "Recommended Fix" in section_titles
    assert "References" in section_titles
    
    # Check content
    assert "reentrancy" in report.executive_summary.lower()
    assert sample_classified_reentrancy.alert.contract_address in report.executive_summary
    
    # Check exploit is included
    poc_section = next(s for s in report.sections if s.title == "Proof of Concept")
    assert "5" in poc_section.content  # Profit in ETH
    assert "ReentrancyAttacker" in poc_section.content


# TEST 2: Bug bounty report for unclassified
def test_bug_bounty_unclassified(reporter, sample_unclassified):
    """Test bug bounty report for unclassified vulnerability"""
    report = reporter.generate_bug_bounty_report(sample_unclassified)
    
    assert report.report_type == "BUG_BOUNTY"
    assert "UNCLASSIFIED" in report.executive_summary or "unclassified" in report.executive_summary.lower()
    
    # Check manual investigation mentioned
    content = "\n".join(s.content for s in report.sections)
    assert "manual investigation" in content.lower() or "unclassified" in content.lower()


# TEST 3: Blue team report generation
def test_blue_team_report_generation(reporter, sample_alert, sample_classified_reentrancy):
    """Test blue team report generation"""
    alerts = [sample_alert]
    classified = [sample_classified_reentrancy]
    
    report = reporter.generate_blue_team_report(alerts, classified, time_window_hours=24)
    
    assert report.report_type == "BLUE_TEAM"
    assert report.total_alerts == 1
    assert report.critical_count == 1
    
    # Check sections
    section_titles = [s.title for s in report.sections]
    assert "Alert Timeline" in section_titles
    assert "Incident Details" in section_titles
    assert "Detection Rules Generated" in section_titles
    assert "Recommendations" in section_titles
    assert "IOC List" in section_titles
    
    # Check timeline present
    timeline_section = next(s for s in report.sections if "Timeline" in s.title)
    assert "Block" in timeline_section.content or "19847293" in timeline_section.content


# TEST 4: Research report generation
def test_research_report_generation(reporter, sample_profile, sample_alert, 
                                   sample_classified_reentrancy, sample_exploit):
    """Test research report generation"""
    alerts = [sample_alert]
    classified = [sample_classified_reentrancy]
    exploits = [sample_exploit]
    
    report = reporter.generate_research_report(
        "0x1234567890123456789012345678901234567890",
        sample_profile,
        alerts,
        classified,
        exploits
    )
    
    assert report.report_type == "RESEARCH"
    
    # Check all sections
    section_titles = [s.title for s in report.sections]
    assert any("Contract Overview" in t for t in section_titles)
    assert any("Behavioral Profile" in t for t in section_titles)
    assert any("Anomaly Detection" in t for t in section_titles)
    assert any("Vulnerability Analysis" in t for t in section_titles)
    assert any("Exploit Validation" in t for t in section_titles)
    assert any("Comparison" in t for t in section_titles)
    assert any("Conclusions" in t for t in section_titles)


# TEST 5: Research report with zero-day candidates
def test_research_report_with_unclassified(reporter, sample_profile, sample_alert, sample_unclassified):
    """Test research report includes zero-day candidates section"""
    alerts = [sample_alert]
    classified = [sample_unclassified]
    exploits = []
    
    report = reporter.generate_research_report(
        "0x1234567890123456789012345678901234567890",
        sample_profile,
        alerts,
        classified,
        exploits
    )
    
    # Check zero-day section exists
    vuln_section = next(s for s in report.sections if "Vulnerability Analysis" in s.title)
    assert "Zero-Day" in vuln_section.content or "Unclassified" in vuln_section.content


# TEST 6: Executive summary generation
def test_executive_summary_generation(reporter, sample_classified_reentrancy):
    """Test executive summary generation"""
    # Create mock reports
    bug_bounty = Report(
        report_id="bb-123",
        report_type="BUG_BOUNTY",
        contract_address="0x1234567890123456789012345678901234567890",
        generated_at=datetime.utcnow().isoformat() + "Z",
        title="Bug Bounty Report",
        executive_summary="Summary",
        sections=[],
        total_anomalies=1,
        total_alerts=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        total_estimated_loss_usd=50000.0,
        output_path=""
    )
    
    blue_team = Report(
        report_id="bt-123",
        report_type="BLUE_TEAM",
        contract_address="0x1234567890123456789012345678901234567890",
        generated_at=datetime.utcnow().isoformat() + "Z",
        title="Blue Team Report",
        executive_summary="Summary",
        sections=[],
        total_anomalies=1,
        total_alerts=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        total_estimated_loss_usd=50000.0,
        output_path=""
    )
    
    reports = [bug_bounty, blue_team]
    
    exec_report = reporter.generate_executive_summary(reports)
    
    assert exec_report.report_type == "EXECUTIVE"
    assert "CRITICAL" in exec_report.executive_summary
    
    # Check sections
    section_titles = [s.title for s in exec_report.sections]
    assert "Key Findings" in section_titles
    assert "Vulnerabilities Found" in section_titles
    assert "Financial Risk Exposure" in section_titles
    assert "Immediate Actions Required" in section_titles
    assert "Assessment Confidence" in section_titles


# TEST 7: File saving
def test_save_report(reporter, sample_classified_reentrancy, sample_exploit, tmp_path):
    """Test report file saving"""
    # Override output directory
    reporter.output_dir = tmp_path
    
    report = reporter.generate_bug_bounty_report(sample_classified_reentrancy, sample_exploit)
    path = reporter.save_report(report)
    
    assert Path(path).exists()
    assert path.endswith(".md")
    
    # Check content
    content = Path(path).read_text()
    assert len(content) > 100
    assert "REENTRANCY" in content or "Reentrancy" in content
    
    # Check JSON exists
    json_path = path.replace(".md", ".json")
    assert Path(json_path).exists()
    
    # Validate JSON
    data = json.loads(Path(json_path).read_text())
    assert data["report_id"] == report.report_id
    assert data["report_type"] == "BUG_BOUNTY"


# TEST 8: Timeline generation
def test_timeline_generation(reporter):
    """Test timeline generation"""
    alerts = [
        AnomalyAlert(
            alert_id=f"alert-{i}",
            contract_address="0x1234567890123456789012345678901234567890",
            tx_hash=f"0xabc{i}",
            block_number=19847290 + i,
            timestamp=1713015600 + i,
            function_sig=func,
            caller="0x9999999999999999999999999999999999999999",
            anomaly_score=score,
            severity=sev,
            z_scores={},
            invariant_violations=[],
            reasons=[],
            eth_value=0,
            estimated_impact_usd=0.0
        )
        for i, (func, sev, score) in enumerate([
            ("transfer()", "NORMAL", 1.0),
            ("deposit()", "NORMAL", 1.5),
            ("withdraw()", "CRITICAL", 8.5),
            ("withdraw()", "HIGH", 6.0),
        ])
    ]
    
    timeline = reporter._generate_timeline(alerts)
    
    assert "19,847,290" in timeline or "19847290" in timeline
    assert "19,847,292" in timeline or "19847292" in timeline  # Critical alert block
    assert "CRITICAL" in timeline
    assert "withdraw" in timeline
    assert "ATTACK" in timeline or "←" in timeline


# TEST 9: Statistics generation
def test_statistics_generation(reporter, sample_alert, sample_classified_reentrancy):
    """Test statistics generation"""
    alerts = [
        sample_alert,
        AnomalyAlert(
            alert_id="alert-2",
            contract_address="0x1234567890123456789012345678901234567890",
            tx_hash="0xdef456",
            block_number=19847294,
            timestamp=1713015601,
            function_sig="transfer(address,uint256)",
            caller="0x8888888888888888888888888888888888888888",
            anomaly_score=6.0,
            severity="HIGH",
            z_scores={"gas": 4.0},
            invariant_violations=[],
            reasons=["Gas spike"],
            eth_value=0,
            estimated_impact_usd=1000.0
        )
    ]
    
    classified = [sample_classified_reentrancy]
    
    stats = reporter._generate_statistics(alerts, classified)
    
    assert stats["total_alerts"] == 2
    assert stats["by_severity"]["CRITICAL"] == 1
    assert stats["by_severity"]["HIGH"] == 1
    assert stats["by_type"]["REENTRANCY"] == 1
    assert stats["total_estimated_loss_usd"] >= 50000.0
    assert stats["avg_anomaly_score"] > 0


# TEST 10: Auto conclusion generation
def test_auto_conclusion_generation(reporter, sample_classified_reentrancy):
    """Test automatic conclusion generation"""
    # Critical findings
    stats_critical = {
        "by_severity": {"CRITICAL": 2, "HIGH": 1},
        "total_estimated_loss_usd": 1500000.0
    }
    classified_critical = [sample_classified_reentrancy]
    
    conclusion = reporter._auto_generate_conclusion(stats_critical, classified_critical)
    assert "critical" in conclusion.lower() or "immediate" in conclusion.lower()
    
    # No findings
    stats_clean = {
        "by_severity": {"CRITICAL": 0, "HIGH": 0},
        "total_estimated_loss_usd": 0.0
    }
    conclusion_clean = reporter._auto_generate_conclusion(stats_clean, [])
    assert "no critical" in conclusion_clean.lower() or "consistent" in conclusion_clean.lower()


# TEST 11: Helper methods
def test_helper_methods(reporter, sample_classified_reentrancy):
    """Test various helper methods"""
    # Risk level calculation
    stats = {"by_severity": {"CRITICAL": 1, "HIGH": 0}}
    assert reporter._calculate_risk_level(stats) == "CRITICAL"
    
    stats = {"by_severity": {"CRITICAL": 0, "HIGH": 1}}
    assert reporter._calculate_risk_level(stats) == "HIGH"
    
    # Recommended action
    action = reporter._get_recommended_action(sample_classified_reentrancy)
    assert "pause" in action.lower() or "immediately" in action.lower()
    
    # Recommendations
    recommendations = reporter._generate_recommendations([sample_classified_reentrancy], stats)
    assert len(recommendations) > 0
    assert any("reentrancy" in r.lower() for r in recommendations)


# TEST 12: Full pipeline report (mocked)
def test_full_pipeline_report_mocked(reporter, sample_profile, sample_alert, 
                                     sample_classified_reentrancy, sample_exploit):
    """Test full pipeline report generation with mocked database"""
    # Mock database responses
    reporter.db.get_profile.return_value = sample_profile
    reporter.db.get_alerts.return_value = [sample_alert]
    reporter.db.get_classified_vulnerabilities.return_value = [sample_classified_reentrancy]
    reporter.db.get_exploits.return_value = [sample_exploit]
    
    # Mock save_report to avoid file I/O
    with patch.object(reporter, 'save_report', return_value="/fake/path.md"):
        reports = reporter.generate_full_pipeline_report("0x1234567890123456789012345678901234567890")
    
    assert len(reports) >= 3  # At least bug bounty, blue team, research, executive
    assert "BLUE_TEAM" in reports
    assert "RESEARCH" in reports
    assert "EXECUTIVE" in reports


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
