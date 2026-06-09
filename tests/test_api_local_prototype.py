import importlib
import hashlib
import time
from pathlib import Path

import pytest

TestClient = pytest.importorskip("fastapi.testclient").TestClient


TOKEN = "friend-prototype-token-1234567890"


def _load_api(monkeypatch):
    monkeypatch.setenv("CHAINEDR_API_KEYS", f"{TOKEN}:free:friend")
    import api.app as api_app

    return importlib.reload(api_app)


def test_local_scan_ui_loads_without_auth(monkeypatch):
    api_app = _load_api(monkeypatch)
    client = TestClient(api_app.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "ChainEDR Local Prototype" in response.text
    assert 'id="source"' in response.text
    assert 'fetch("/scan"' in response.text
    assert "escapeHtml" in response.text


def test_api_scan_uses_analyzer_confidence_contract(monkeypatch):
    api_app = _load_api(monkeypatch)
    client = TestClient(api_app.app)
    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DelegatedGate {
    function gated() external view {
        require(tx.origin == msg.sender, "EOA only");
    }
}
"""

    response = client.post(
        "/scan",
        headers={"X-API-Key": TOKEN},
        json={
            "contract_name": "DelegatedGate",
            "source_code": source,
            "deep": True,
            "no_external": True,
        },
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["tier"] == "free"
    assert data["scan_id"].startswith(
        hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    )
    assert data["findings"]
    first = data["findings"][0]
    assert first["rule_id"].startswith("AA7702")
    assert first["analysis_depth"]
    assert first["reviewer_confidence"]["grade"]
    assert first["reviewer_confidence"]["tier"] in {
        "CONFIRMED",
        "CANDIDATE",
        "INFORMATIONAL",
    }
    assert data["by_reviewer_confidence"]
    assert data["by_reviewer_tier"]


def test_api_scan_rejects_wrong_token(monkeypatch):
    api_app = _load_api(monkeypatch)
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        headers={"X-API-Key": "wrong-token-1234567890"},
        json={"source_code": "contract Clean {}", "contract_name": "Clean"},
    )

    assert response.status_code == 401


def test_api_scan_rejects_oversized_source(monkeypatch):
    monkeypatch.setenv("CHAINEDR_MAX_SOURCE_BYTES", "10")
    api_app = _load_api(monkeypatch)
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        headers={"X-API-Key": TOKEN},
        json={"source_code": "contract TooLarge {}", "contract_name": "TooLarge"},
    )

    assert response.status_code == 413
    assert "Source is too large" in response.json()["detail"]


def test_api_scan_reports_timeout(monkeypatch):
    monkeypatch.setenv("CHAINEDR_SCAN_TIMEOUT_SECONDS", "0.01")
    api_app = _load_api(monkeypatch)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "src"))
    from eip7702_detector import EIP7702Detector

    def slow_scan(self, *_args, **_kwargs):
        time.sleep(0.1)
        return [], {}

    monkeypatch.setattr(EIP7702Detector, "scan_files", slow_scan)
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        headers={"X-API-Key": TOKEN},
        json={"source_code": "contract Slow {}", "contract_name": "Slow"},
    )

    assert response.status_code == 504
    assert "timed out" in response.json()["detail"]


def test_api_usage_can_persist_in_sqlite(monkeypatch, tmp_path):
    usage_db = tmp_path / "usage.sqlite"
    monkeypatch.setenv("CHAINEDR_USAGE_DB", str(usage_db))
    api_app = _load_api(monkeypatch)
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        headers={"X-API-Key": TOKEN},
        json={"source_code": "contract Clean {}", "contract_name": "Clean"},
    )

    assert response.status_code == 200, response.text
    key_hash = api_app._hash_key(TOKEN)
    assert usage_db.exists()
    assert api_app._get_usage(key_hash) == 1

    reloaded = importlib.reload(api_app)
    assert reloaded._get_usage(key_hash) == 1


def test_api_scan_reports_analyzer_failure(monkeypatch):
    api_app = _load_api(monkeypatch)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "src"))
    from eip7702_detector import EIP7702Detector

    def fail_scan(self, *_args, **_kwargs):
        raise RuntimeError("scan unavailable")

    monkeypatch.setattr(EIP7702Detector, "scan_files", fail_scan)
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        headers={"X-API-Key": TOKEN},
        json={"source_code": "contract Clean {}", "contract_name": "Clean"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Analyzer scan failed: scan unavailable"
