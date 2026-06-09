from chainedr.verifier import FindingVerifier

def test_finding_verifier_submission():
    verifier = FindingVerifier()
    trust_model = {"permissionless_functions": ["deposit"]}
    finding = {"function": "deposit", "severity": "HIGH"}
    
    result = verifier.verify(finding, trust_model)
    assert result["verdict"] == "SUBMIT"

def test_finding_verifier_no_submission():
    verifier = FindingVerifier()
    trust_model = {"restricted_functions": {"setFee": "onlyOwner"}}
    finding = {"function": "setFee", "severity": "HIGH"}
    
    result = verifier.verify(finding, trust_model)
    assert result["verdict"] == "DO_NOT_SUBMIT"
    assert result["adjusted_severity"] == "INFO"
