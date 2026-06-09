"""test_doppler_regression.py — Verify that trust-aware analysis correctly handles lockDuration=0"""

from chainedr.verifier import FindingVerifier

def test_doppler_lockduration_with_trust():
    """
    With trust analysis, ChainEDR should:
    1. Still FLAG lockDuration=0 as a pattern (correct — missing validation)
    2. Determine trust_level = TRUSTED (lock restricted to onlyApprovedMigrator)
    3. Downgrade severity from MEDIUM to INFO
    4. FindingVerifier says: DO_NOT_SUBMIT
    
    This matches Cantina's rejection reasoning.
    """
    trust_model = {
        "trusted_roles": ["owner", "approvedMigrator"],
        "restricted_functions": {
            "lock": "onlyApprovedMigrator",
            "approveMigrator": "onlyOwner",
            "revokeMigrator": "onlyOwner",
        },
        "permissionless_functions": ["collectFees", "updateBeneficiary"],
    }
    
    finding = {
        "function": "lock",
        "parameter": "lockDuration",
        "issue": "No minimum value check, accepts 0",
        "severity": "MEDIUM",
        "requires_setup_by_trusted_role": True,
    }
    
    verifier = FindingVerifier()
    result = verifier.verify(finding, trust_model)
    
    assert result["verdict"] == "DO_NOT_SUBMIT"
    assert result["adjusted_severity"] == "INFO"
    assert any(c["check"] == "trust_model" and c["result"] == "FAIL" for c in result["checks"])

    print("CORRECT: Trust-aware analysis would NOT have submitted Doppler finding")
    print(f"Verdict: {result['verdict']}")
    print(f"Severity: {result['original_severity']} → {result['adjusted_severity']}")
    for check in result["checks"]:
        print(f"  [{check['result']}] {check['check']}: {check['reason']}")
