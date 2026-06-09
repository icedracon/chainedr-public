from chainedr.hunter import Hunter

def test_trace_parameter_trust_owner():
    hunter = Hunter()
    func = {"name": "updateFees", "stateMutability": "nonpayable", "inputs": [{"name": "newFee"}]}
    source_code = {"updateFees": "function updateFees(uint newFee) public onlyOwner { fee = newFee; }"}
    
    trust_level = hunter._trace_parameter_trust(func, func["inputs"][0], source_code)
    assert trust_level == "TRUSTED"
