# Agent Security Lab V2

V2 keeps V1's Gateway/Runtime boundary and adds credential guardrails,
structured logs, and persistent security events.

## Start

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Gateway: `http://localhost:8082`  
Swagger: `http://localhost:8082/docs`

## Safe request

```powershell
$body = @{ input = "What is a strong password policy?" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8082/v1/agents/basic-agent/invoke `
  -ContentType application/json `
  -Body $body
```

## Blocked input

```powershell
$body = @{ input = "password=Secret123!" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8082/v1/agents/basic-agent/invoke `
  -ContentType application/json `
  -Body $body
```

The request returns HTTP 403 and never reaches the Runtime.

## Inspect logs and events

```powershell
docker compose logs -f gateway runtime
Get-Content .\data\security-events.jsonl -Wait
```

Detected credentials are replaced with `[REDACTED]` before an event is stored.
Event capture defaults to `redacted`; use `metadata` when request/response content
must not be retained.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The output-blocking scenario is covered by an automated test because the normal
mock LLM echoes safe input and therefore cannot naturally emit a new credential.
