from chainedr.hunter import Hunter

def test_trace_parameter_trust_public():
    hunter = Hunter()
    func = {"name": "deposit", "stateMutability": "payable", "inputs": [{"name": "amount"}]}
    source_code = {"deposit": "function deposit(uint amount) public { balance += amount; }"}
    
    trust_level = hunter._trace_parameter_trust(func, func["inputs"][0], source_code)
    assert trust_level == "UNTRUSTED"
