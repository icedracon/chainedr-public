from chainedr.classifier import Classifier
from chainedr.models import AnomalyAlert, ClassifiedVulnerability

def test_classifier_with_trust_downgrade():
    classifier = Classifier.__new__(Classifier)
    classifier.known_attacks_db = {}
    
    alert = AnomalyAlert(
        alert_id="1234",
        tx_hash="0x123",
        function_sig="setFees",
        contract_address="0xabc",
        severity="HIGH",
        estimated_impact_usd=0,
        block_number=1,
        timestamp=1,
        caller="0x",
        anomaly_score=1.0,
        z_scores={},
        invariant_violations=[],
        reasons=[],
        eth_value=0
    )
    
    def mock_classify(al):
        return ClassifiedVulnerability(
            classification_id="123",
            alert=al,
            vulnerability_type="LOGIC",
            confidence=0.8,
            severity="HIGH",
            cvss_score=8.5,
            estimated_loss_usd=0,
            affected_functions=["setFees"],
            attack_vector="Test",
            attack_pattern=None
        )
    classifier.classify = mock_classify
    
    trust_model = {"restricted_functions": {"setFees": "onlyOwner"}}
    
    result = classifier.classify_with_trust(alert, trust_model)
    assert result.confidence == 0.5
    assert "REQUIRES_TRUSTED_ROLE" in result.flags
    assert result.severity == "MEDIUM"
