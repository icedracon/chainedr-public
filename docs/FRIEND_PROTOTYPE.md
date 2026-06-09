# Friend And Auditor Prototype Setup

This path is for sharing a local ChainEDR Analyzer prototype with a trusted friend or reviewer without sending real tokens, RPC keys, wallet keys, or GitHub credentials.

## Install

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .\src
```

For the local HTTP API prototype:

```powershell
python -m pip install -e ".\src[api]"
```

## Configure

Create a local environment file:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the generated value into `CHAINEDR_API_KEYS` using this format:

```text
CHAINEDR_API_KEYS=generated-token-here:free:friend
```

Do not put GitHub tokens, wallet keys, deployer keys, private RPC URLs, or paid API keys in chat. If a token was shared by mistake, rotate it before the next demo.

## CLI Smoke Test

```powershell
chainedr scan .\benchmarks\eip7702_sandbox\benign --no-external --json out\friend-smoke.json
```

The command should create `out\friend-smoke.json` and should not require live RPC credentials.

## API Smoke Test

Start the local API:

```powershell
uvicorn api.app:app --host 127.0.0.1 --port 8080
```

Open the local prototype page:

```text
http://127.0.0.1:8080/
```

Paste the generated token into the API key field. The page runs an offline scan
by default and shows severity, rule id, analysis depth, proof status, and the
`reviewer_confidence` evidence grade for each finding.

For a terminal smoke test, replace the token with the generated value from
`.env`:

```powershell
$token = "generated-token-here"
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod http://127.0.0.1:8080/usage -Headers @{"X-API-Key"=$token}
$body = @{
  contract_name = "Clean"
  source_code = "// SPDX-License-Identifier: MIT`npragma solidity ^0.8.20;`ncontract Clean {}"
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8080/scan -Method Post -Headers @{"X-API-Key"=$token} -ContentType "application/json" -Body $body
```

## Token Rules

- `.env` is ignored by git; `.env.example` is the only environment file meant to be committed.
- API keys must be at least 16 characters.
- The API stores only SHA-256 hashes of configured keys in memory.
- Logs and status output redact URL tokens, API keys, secrets, and RPC credentials before printing.
- Keep CORS on local origins unless you intentionally deploy behind HTTPS.
