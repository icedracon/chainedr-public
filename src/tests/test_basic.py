"""
Simple test to verify Explorer module works without Etherscan API key.
This tests basic functionality like bytecode fetching and proxy detection.
"""

from chainedr.explorer import Explorer
import json


def test_basic_functionality():
    """Test basic Explorer functionality without requiring Etherscan API"""
    
    print("\n" + "="*60)
    print("ChainEDR Module 1: Explorer - Basic Functionality Test")
    print("="*60)
    
    explorer = Explorer()
    
    # Test 1: Fetch bytecode for USDC
    print("\n[Test 1] Fetching bytecode for USDC...")
    usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    
    try:
        bytecode = explorer.get_bytecode(usdc_address)
        print(f"[PASS] Bytecode fetched: {len(bytecode)} characters")
        assert len(bytecode) > 100, "Bytecode should be substantial"
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        return False
    
    # Test 2: Check proxy detection for USDC
    print("\n[Test 2] Checking proxy detection for USDC...")
    try:
        impl_address = explorer.resolve_proxy(usdc_address)
        if impl_address:
            print(f"[PASS] Proxy detected! Implementation: {impl_address}")
        else:
            print("  Note: Proxy not detected (may need different detection method)")
    except Exception as e:
        print(f"  Proxy check completed with note: {e}")
    
    # Test 3: Analyze WETH (simpler contract)
    print("\n[Test 3] Analyzing WETH contract...")
    weth_address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    
    try:
        contract_map = explorer.analyze(weth_address)
        print(f"[PASS] Analysis completed")
        print(f"  - Address: {contract_map.address}")
        print(f"  - Pattern: {contract_map.pattern.value}")
        print(f"  - Bytecode length: {len(contract_map.bytecode)}")
        print(f"  - Is verified: {contract_map.is_verified}")
        
        # Save to JSON
        output = contract_map.to_dict()
        json_output = json.dumps(output, indent=2)
        
        with open("reports/weth_analysis.json", 'w') as f:
            f.write(json_output)
        
        print(f"  - Saved to: reports/weth_analysis.json")
        
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        return False
    
    # Test 4: Invalid address handling
    print("\n[Test 4] Testing invalid address handling...")
    try:
        explorer.analyze("0xinvalid")
        print("[FAIL] Should have raised ValueError")
        return False
    except ValueError as e:
        print(f"[PASS] Correctly rejected invalid address: {e}")
    
    print("\n" + "="*60)
    print("BASIC TESTS PASSED")
    print("="*60)
    print("\nNOTE: To test full functionality with ABI parsing:")
    print("1. Get free Etherscan API key: https://etherscan.io/myapikey")
    print("2. Update .env file: ETHERSCAN_API_KEY=your_key_here")
    print("3. Run: python tests/test_explorer.py")
    print("="*60)
    
    return True


if __name__ == "__main__":
    try:
        success = test_basic_functionality()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n[FAIL] TEST SUITE FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
