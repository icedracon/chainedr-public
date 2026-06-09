from src.config import Config, redact_secret, redact_sensitive, redact_url


def test_redact_secret_keeps_shape_without_leaking_middle():
    secret = "abcdefghijklmnopqrstuvwxyz0123456789"

    redacted = redact_secret(secret)

    assert redacted.startswith("abcd")
    assert redacted.endswith("6789")
    assert "efghijklmnopqrstuvwxyz012345" not in redacted


def test_redact_sensitive_masks_rpc_path_token():
    rpc_path_value = "publicTestRpcPathValue1234567890"
    rpc_url = f"https://eth-mainnet.g.alchemy.com/v2/{rpc_path_value}"

    redacted = redact_sensitive(rpc_url, name="rpc_url")

    assert rpc_path_value not in redacted
    assert redacted == "https://eth-mainnet.g.alchemy.com/v2/***"


def test_redact_sensitive_masks_secret_assignments():
    query_value = "publicTestApiValue123"
    bearer_value = "publicBearerValue123"
    message = f"request failed with api_key={query_value} and token: {bearer_value}"

    redacted = redact_sensitive(message)

    assert query_value not in redacted
    assert bearer_value not in redacted
    assert "api_key=***" in redacted
    assert "token: ***" in redacted


def test_redact_url_masks_sensitive_query_values():
    query_value = "publicTestApiValue123"
    url = f"https://api.etherscan.io/v2/api?module=contract&apikey={query_value}&address=0x123"

    redacted = redact_url(url)

    assert query_value not in redacted
    assert "apikey=%2A%2A%2A" in redacted
    assert "address=0x123" in redacted


def test_etherscan_url_uses_encoded_query(monkeypatch):
    query_value = "publicTestApiValue123"
    monkeypatch.setattr(Config, "ETHERSCAN_API_KEY", query_value)

    url = Config.get_etherscan_url(
        "contract",
        "getsourcecode",
        address="0x123",
        comment="space value",
    )

    assert f"apikey={query_value}" in url
    assert "comment=space+value" in url
    assert "space value" not in url
