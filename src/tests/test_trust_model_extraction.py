from chainedr.explorer import Explorer

def test_extract_trust_model():
    explorer = Explorer.__new__(Explorer)
    source_code = {
        "setAdmin": "function setAdmin(address admin) external onlyOwner",
        "updateFee": "function updateFee(uint fee) public onlyRole(FEE_UPDATER)",
        "deposit": "function deposit() external payable"
    }
    
    trust_model = explorer.extract_trust_model(abi=[], source_code=source_code)
    
    assert "owner" in trust_model["trusted_roles"]
    assert "role" in trust_model["trusted_roles"]
    assert "setAdmin" in trust_model["restricted_functions"]
    assert "deposit" in trust_model["permissionless_functions"]
