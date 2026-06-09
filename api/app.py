"""
ChainEDR local prototype API.

The API is for trusted friend/auditor demos. It uses generated local tokens,
offline scans by default, and the same reviewer-confidence evidence contract as
the CLI JSON output.
"""
import os
import time
import hashlib
import secrets
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Optional
from pathlib import Path
from datetime import datetime, date, timezone

try:
    from fastapi import FastAPI, HTTPException, Depends, Header
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    raise RuntimeError("pip install fastapi uvicorn pydantic")


def _load_local_env() -> None:
    """Load .env for local prototypes without requiring python-dotenv."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for env_path in candidates:
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        break


_load_local_env()

app = FastAPI(
    title="ChainEDR API",
    version="3.0.0",
    description="Local ChainEDR Analyzer prototype API",
)


def _cors_origins() -> list[str]:
    raw = os.getenv(
        "CHAINEDR_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
    )
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["http://localhost:3000"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# --- License tiers ---
TIERS = {
    "free":       {"daily_limit": 10,   "llm_triage": False, "poc_gen": False,  "price_mo": 0},
    "pro":        {"daily_limit": 500,  "llm_triage": True,  "poc_gen": False,  "price_mo": 49},
    "enterprise": {"daily_limit": 0,    "llm_triage": True,  "poc_gen": True,   "price_mo": 299},
}

# Usage tracking (in-memory; replace with SQLite/Redis in prod)
_usage: dict[str, dict] = {}


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _load_api_keys() -> dict[str, dict]:
    """
    Load API keys from CHAINEDR_API_KEYS.

    Format:
      token:tier:owner,another-token:free:friend

    No API key is embedded in source. For local demos, copy .env.example to
    .env and generate a random token.
    """
    loaded: dict[str, dict] = {}
    raw = os.getenv("CHAINEDR_API_KEYS", "")
    for item in raw.replace("\n", ",").split(","):
        item = item.strip()
        if not item:
            continue
        parts = [part.strip() for part in item.split(":", 2)]
        raw_key = parts[0]
        tier = parts[1] if len(parts) > 1 and parts[1] else "free"
        owner = parts[2] if len(parts) > 2 and parts[2] else "friend"
        if tier not in TIERS:
            raise RuntimeError(f"Unknown ChainEDR API tier in CHAINEDR_API_KEYS: {tier}")
        if len(raw_key) < 16:
            raise RuntimeError("CHAINEDR_API_KEYS entries must be at least 16 characters")
        loaded[_hash_key(raw_key)] = {
            "tier": tier,
            "owner": owner,
            "created": "env",
        }
    return loaded


_api_keys: dict[str, dict] = _load_api_keys()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _max_source_bytes() -> int:
    return max(0, _env_int("CHAINEDR_MAX_SOURCE_BYTES", 250_000))


def _scan_timeout_seconds() -> float:
    return max(0.0, _env_float("CHAINEDR_SCAN_TIMEOUT_SECONDS", 30.0))


def _source_size_bytes(source_code: str) -> int:
    return len((source_code or "").encode("utf-8"))


def _build_scan_id(contract_name: str, source_code: str) -> str:
    source_hash = hashlib.sha256((source_code or "").encode("utf-8")).hexdigest()[:12]
    nonce = f"{time.time_ns():x}"[-10:]
    safe_contract = _safe_contract_name(contract_name).lower()[:24]
    return f"{source_hash}-{safe_contract}-{nonce}"


def _usage_db_path() -> Optional[Path]:
    raw = os.getenv("CHAINEDR_USAGE_DB", "").strip()
    return Path(raw) if raw else None


def _ensure_usage_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_limits (
                key_hash TEXT PRIMARY KEY,
                usage_date TEXT NOT NULL,
                request_count INTEGER NOT NULL
            )
            """
        )


def _get_usage_from_db(path: Path, key_hash: str, today: str) -> int:
    _ensure_usage_db(path)
    with sqlite3.connect(path) as db:
        row = db.execute(
            "SELECT usage_date, request_count FROM usage_limits WHERE key_hash = ?",
            (key_hash,),
        ).fetchone()
    if not row or row[0] != today:
        return 0
    return int(row[1] or 0)


def _increment_usage_in_db(path: Path, key_hash: str, today: str) -> None:
    _ensure_usage_db(path)
    current = _get_usage_from_db(path, key_hash, today) + 1
    with sqlite3.connect(path) as db:
        db.execute(
            """
            INSERT INTO usage_limits (key_hash, usage_date, request_count)
            VALUES (?, ?, ?)
            ON CONFLICT(key_hash) DO UPDATE SET
                usage_date = excluded.usage_date,
                request_count = excluded.request_count
            """,
            (key_hash, today, current),
        )


def _get_usage(key_hash: str) -> int:
    today = str(date.today())
    db_path = _usage_db_path()
    if db_path:
        return _get_usage_from_db(db_path, key_hash, today)
    rec = _usage.get(key_hash, {})
    if rec.get("date") != today:
        return 0
    return rec.get("count", 0)


def _increment_usage(key_hash: str):
    today = str(date.today())
    db_path = _usage_db_path()
    if db_path:
        _increment_usage_in_db(db_path, key_hash, today)
        return
    rec = _usage.get(key_hash, {"date": today, "count": 0})
    if rec["date"] != today:
        rec = {"date": today, "count": 0}
    rec["count"] += 1
    _usage[key_hash] = rec


def _auth(x_api_key: str = Header(..., alias="X-API-Key")) -> dict:
    if not _api_keys:
        raise HTTPException(
            status_code=503,
            detail="API keys are not configured. Set CHAINEDR_API_KEYS in .env.",
        )
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    info = None
    for stored_hash, stored_info in _api_keys.items():
        if secrets.compare_digest(stored_hash, key_hash):
            info = stored_info
            break
    if not info:
        raise HTTPException(status_code=401, detail="Invalid API key")
    tier = TIERS[info["tier"]]
    limit = tier["daily_limit"]
    if limit > 0:
        used = _get_usage(key_hash)
        if used >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Daily limit reached ({limit} req/day for {info['tier']} tier). Upgrade at chainedr.dev/pricing"
            )
    _increment_usage(key_hash)
    return {"key_hash": key_hash, **info, **tier}


# --- Request/Response models ---
class ScanRequest(BaseModel):
    source_code: str
    contract_name: str = "Unknown"
    llm_triage: bool = False
    min_severity: str = "LOW"
    deep: bool = True
    no_external: bool = True


class FindingOut(BaseModel):
    id: str
    rule_id: str
    severity: str
    title: str
    description: str
    location: str
    exploitable: bool
    confidence: float
    analysis_depth: str
    reviewer_confidence: dict
    proof_status: Optional[str] = None
    proof_readiness: Optional[str] = None
    proof_objective: Optional[str] = None
    fix: str = ""
    llm_verdict: Optional[str] = None
    llm_reason: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    contract: str
    findings: list[FindingOut]
    by_reviewer_confidence: dict[str, int]
    by_reviewer_tier: dict[str, int]
    critical: int
    high: int
    medium: int
    low: int
    duration_ms: float
    tier: str


# --- Endpoints ---

_LOCAL_SCAN_UI = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ChainEDR Local Prototype</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #202529;
      --muted: #687078;
      --line: #d7dce0;
      --panel: #f8f9fa;
      --field: #ffffff;
      --accent: #0f766e;
      --danger: #ba1a1a;
      --warn: #9a5b00;
      --good: #126b39;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif;
      color: var(--ink);
      background: #f1f3f4;
    }
    header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--line);
      background: #ffffff;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .mark {
      width: 34px;
      height: 34px;
      border-radius: 8px;
      background: conic-gradient(from 210deg, #0f766e, #92c5b8, #f3c567, #0f766e);
      border: 1px solid #0c5f58;
    }
    h1 {
      font-size: 17px;
      margin: 0;
      font-weight: 650;
      letter-spacing: 0;
    }
    main {
      display: grid;
      grid-template-columns: minmax(320px, 460px) minmax(0, 1fr);
      gap: 16px;
      padding: 16px;
      max-width: 1440px;
      margin: 0 auto;
    }
    section {
      min-width: 0;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }
    label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin: 10px 0 4px;
    }
    input, select, textarea, button {
      width: 100%;
      font: inherit;
      border-radius: 6px;
      border: 1px solid var(--line);
      background: var(--field);
      color: var(--ink);
    }
    input, select {
      min-height: 36px;
      padding: 7px 9px;
    }
    textarea {
      min-height: 430px;
      resize: vertical;
      padding: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .checks {
      display: flex;
      gap: 14px;
      margin: 10px 0 12px;
      flex-wrap: wrap;
    }
    .checks label {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin: 0;
      color: var(--ink);
    }
    .checks input { width: auto; min-height: auto; }
    button {
      min-height: 40px;
      background: var(--accent);
      color: white;
      border-color: var(--accent);
      cursor: pointer;
      font-weight: 650;
    }
    button:disabled { opacity: .55; cursor: wait; }
    .summary {
      display: grid;
      grid-template-columns: repeat(6, minmax(84px, 1fr));
      gap: 8px;
      margin-bottom: 12px;
    }
    .metric, .finding {
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
    }
    .metric strong {
      display: block;
      font-size: 20px;
      line-height: 1.2;
    }
    .metric span {
      color: var(--muted);
      font-size: 12px;
    }
    .finding {
      margin-bottom: 10px;
    }
    .finding-head {
      display: grid;
      grid-template-columns: auto auto 1fr auto;
      gap: 8px;
      align-items: center;
      margin-bottom: 7px;
    }
    .pill {
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      border: 1px solid var(--line);
      background: #fff;
      white-space: nowrap;
    }
    .critical, .high { color: var(--danger); border-color: #e7b6b6; }
    .medium { color: var(--warn); border-color: #e9cf9f; }
    .low, .info { color: var(--good); border-color: #a9d8bc; }
    .grade-A { background: #dff3e6; border-color: #95d2ad; color: #0b5c31; }
    .grade-B { background: #e4f1f6; border-color: #9bc9db; color: #115368; }
    .grade-C { background: #fff0cf; border-color: #e7c575; color: #704800; }
    .grade-D { background: #f7e4e0; border-color: #dda49b; color: #8a2418; }
    .title {
      font-weight: 650;
      overflow-wrap: anywhere;
    }
    .desc {
      color: #34413d;
      margin: 0 0 8px;
    }
    .meta {
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .empty {
      padding: 24px;
      color: var(--muted);
      text-align: center;
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: #ffffff;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 640px) {
      header { padding: 12px; }
      main { padding: 10px; }
      .row { grid-template-columns: 1fr; }
      textarea { min-height: 320px; }
      .finding-head { grid-template-columns: 1fr; align-items: start; }
      .pill { width: max-content; max-width: 100%; white-space: normal; overflow-wrap: anywhere; }
    }
  </style>
</head>
<body>
  <header>
    <div class="mark" aria-hidden="true"></div>
    <h1>ChainEDR Local Prototype</h1>
  </header>
  <main>
    <section class="panel">
      <label for="token">API key</label>
      <input id="token" type="password" autocomplete="off" />
      <div class="row">
        <div>
          <label for="contract">Contract</label>
          <input id="contract" value="DelegatedGate" />
        </div>
        <div>
          <label for="severity">Minimum severity</label>
          <select id="severity">
            <option>LOW</option>
            <option>MEDIUM</option>
            <option>HIGH</option>
            <option>CRITICAL</option>
          </select>
        </div>
      </div>
      <div class="checks">
        <label><input id="deep" type="checkbox" checked /> Deep</label>
        <label><input id="offline" type="checkbox" checked /> Offline</label>
      </div>
      <label for="source">Source</label>
      <textarea id="source">// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DelegatedGate {
    function gated() external view {
        require(tx.origin == msg.sender, "EOA only");
    }
}</textarea>
      <button id="scan">Run Scan</button>
    </section>
    <section>
      <div id="summary" class="summary"></div>
      <div id="results" class="empty">No scan yet</div>
    </section>
  </main>
  <script>
    const byId = (id) => document.getElementById(id);
    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char]));
    const cssToken = (value) => String(value ?? "").replace(/[^A-Za-z0-9_-]/g, "");
    function metric(label, value) {
      return `<div class="metric"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>`;
    }
    function render(data) {
      const byTier = data.by_reviewer_tier || {};
      byId("summary").innerHTML = [
        metric("Findings", data.findings.length),
        metric("Critical", data.critical),
        metric("High", data.high),
        metric("Confirmed", byTier.CONFIRMED || 0),
        metric("Candidates", byTier.CANDIDATE || 0),
        metric("Tier", data.tier),
      ].join("");
      if (!data.findings.length) {
        byId("results").className = "empty";
        byId("results").textContent = "Clean scan";
        return;
      }
      byId("results").className = "";
      byId("results").innerHTML = data.findings.map((f) => {
        const rc = f.reviewer_confidence || {};
        const sev = cssToken(String(f.severity ?? "").toLowerCase()) || "info";
        const grade = escapeHtml(rc.grade || "?");
        const gradeClass = cssToken(rc.grade || "unknown");
        const tier = escapeHtml(rc.tier || "CANDIDATE");
        const evidence = (Array.isArray(rc.evidence) ? rc.evidence : []).map(escapeHtml).join(", ") || "none";
        const gaps = (Array.isArray(rc.gaps) ? rc.gaps : []).map(escapeHtml).join(", ") || "none";
        return `<article class="finding">
          <div class="finding-head">
            <span class="pill ${sev}">${escapeHtml(f.severity)}</span>
            <span class="pill">${escapeHtml(f.rule_id)}</span>
            <div class="title">${escapeHtml(f.title)}</div>
            <span class="pill grade-${gradeClass}">${tier} - ${grade} ${escapeHtml(rc.score)}/100</span>
          </div>
          <p class="desc">${escapeHtml(f.description)}</p>
          <div class="meta">${escapeHtml(f.location)} - ${escapeHtml(f.analysis_depth)} - ${escapeHtml(f.proof_status || "static")}</div>
          <div class="meta">Evidence: ${evidence}</div>
          <div class="meta">Gaps: ${gaps}</div>
        </article>`;
      }).join("");
    }
    byId("scan").addEventListener("click", async () => {
      const button = byId("scan");
      button.disabled = true;
      button.textContent = "Scanning";
      try {
        const response = await fetch("/scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": byId("token").value,
          },
          body: JSON.stringify({
            contract_name: byId("contract").value,
            source_code: byId("source").value,
            min_severity: byId("severity").value,
            deep: byId("deep").checked,
            no_external: byId("offline").checked,
          }),
        });
        if (!response.ok) {
          const err = await response.json().catch(() => ({}));
          throw new Error(err.detail || response.statusText);
        }
        render(await response.json());
      } catch (error) {
        byId("summary").innerHTML = "";
        byId("results").className = "empty";
        byId("results").textContent = error.message;
      } finally {
        button.disabled = false;
        button.textContent = "Run Scan";
      }
    });
  </script>
</body>
</html>"""

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "time": datetime.now(timezone.utc).isoformat(),
        "api_keys_configured": bool(_api_keys),
    }


@app.get("/", response_class=HTMLResponse)
def local_scan_ui():
    return HTMLResponse(_LOCAL_SCAN_UI)


@app.get("/tiers")
def tiers():
    return TIERS


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest, auth: dict = Depends(_auth)):
    import sys
    import tempfile

    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    t0 = time.time()
    safe_name = _safe_contract_name(req.contract_name)
    source_bytes = _source_size_bytes(req.source_code)
    max_bytes = _max_source_bytes()
    if max_bytes and source_bytes > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Source is too large ({source_bytes} bytes). Limit is {max_bytes} bytes.",
        )
    scan_id = _build_scan_id(req.contract_name, req.source_code)

    with tempfile.TemporaryDirectory(prefix="chainedr-api-") as tmp_dir:
        source_path = Path(tmp_dir) / f"{safe_name}.sol"
        source_path.write_text(req.source_code, encoding="utf-8")
        try:
            # Route the API scan through the Analyzer's EIP-7702 detector
            # directly. This avoids importing the deleted legacy Hunter
            # and keeps the API on the same code path as `chainedr scan`.
            from reviewer_confidence import reviewer_confidence_for_finding
            from eip7702_detector import EIP7702Detector

            timeout_s = _scan_timeout_seconds()

            def _run_scan() -> list[dict]:
                det = EIP7702Detector()
                sources = {f"{safe_name}.sol": req.source_code}
                project_findings, _ctx = det.scan_files(
                    sources, deep=bool(req.deep)
                )
                out: list[dict] = []
                for fname, f7702 in project_findings:
                    fd = f7702.to_dict()
                    fd.setdefault("file_path", fname)
                    fd.setdefault("category", "eip7702")
                    fd.setdefault(
                        "severity", str(getattr(f7702, "severity", "LOW"))
                    )
                    out.append(fd)
                return out

            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(_run_scan)
            try:
                raw_findings = future.result(timeout=timeout_s or None)
            except FutureTimeout as exc:
                future.cancel()
                raise HTTPException(
                    status_code=504,
                    detail=f"Analyzer scan timed out after {timeout_s:g} seconds.",
                ) from exc
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Analyzer scan failed: {exc}") from exc

    # LLM triage if pro/enterprise and requested
    if req.llm_triage and auth.get("llm_triage"):
        try:
            from llm_triage import bulk_triage
            payload = [
                {
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "contract": req.contract_name,
                    "code": req.source_code[:500],
                    "severity": f.get("severity", "MEDIUM"),
                }
                for f in raw_findings
            ]
            triaged = bulk_triage(payload)
            for i, t in enumerate(triaged):
                if i < len(raw_findings):
                    raw_findings[i]["llm_triage"] = t.get("llm_triage", {})
        except Exception:
            pass

    # Filter by min_severity
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_sev = sev_order.get(req.min_severity.upper(), 0)

    findings_out = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_reviewer_confidence: dict[str, int] = {}
    by_reviewer_tier: dict[str, int] = {}
    for i, f in enumerate(raw_findings):
        sev = f.get("severity", "LOW").upper()
        if sev_order.get(sev, 0) < min_sev:
            continue
        llt = f.get("llm_triage", {})
        reviewer_confidence = f.get("reviewer_confidence") or (
            reviewer_confidence_for_finding(f) if reviewer_confidence_for_finding else {}
        )
        grade = reviewer_confidence.get("grade", "unknown")
        by_reviewer_confidence[grade] = by_reviewer_confidence.get(grade, 0) + 1
        reviewer_tier = reviewer_confidence.get("tier", "unknown")
        by_reviewer_tier[reviewer_tier] = by_reviewer_tier.get(reviewer_tier, 0) + 1
        findings_out.append(FindingOut(
            id=f"F{i+1:03d}",
            rule_id=f.get("rule_id") or f.get("check") or f.get("check_id") or "UNKNOWN",
            severity=sev,
            title=f.get("title", "Unknown"),
            description=f.get("description", ""),
            location=f.get("location", ""),
            exploitable=f.get("exploitable", False),
            confidence=float(f.get("confidence", 0)),
            analysis_depth=f.get("analysis_depth", "static_heuristic"),
            reviewer_confidence=reviewer_confidence,
            proof_status=f.get("proof_status"),
            proof_readiness=f.get("proof_readiness"),
            proof_objective=f.get("proof_objective"),
            fix=f.get("recommendation") or f.get("fix") or f.get("fix_suggestion") or "",
            llm_verdict=llt.get("verdict"),
            llm_reason=llt.get("reason"),
        ))
        key = sev.lower() if sev.lower() in counts else None
        if key:
            counts[key] += 1

    return ScanResponse(
        scan_id=scan_id,
        contract=req.contract_name,
        findings=findings_out,
        by_reviewer_confidence=by_reviewer_confidence,
        by_reviewer_tier=by_reviewer_tier,
        duration_ms=round((time.time() - t0) * 1000, 1),
        tier=auth["tier"],
        **counts,
    )


@app.get("/usage")
def usage(auth: dict = Depends(_auth)):
    used = _get_usage(auth["key_hash"])
    limit = auth["daily_limit"]
    return {
        "tier": auth["tier"],
        "used_today": used,
        "limit": limit if limit > 0 else "unlimited",
        "remaining": max(0, limit - used) if limit > 0 else "unlimited",
    }


def _safe_contract_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value or "Contract").strip("_")
    if not name or name[0].isdigit():
        name = f"Contract_{name or 'Unknown'}"
    return name[:80]


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
