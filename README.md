# Guardrail Red-Team Round-Trip API

Security endpoint that acts as a guardrail in front of two tools: `read_file(path)` and `fetch_url(url)`.

## Endpoint Contract

- **Method**: `POST`
- **Path**: `/check` (or `/`)
- **Request Body**:
```json
{ "tool": "read_file", "arguments": { "path": "/srv/agent-redteam/sandbox-2c3b759c51/notes/report.txt" } }
```
```json
{ "tool": "fetch_url", "arguments": { "url": "https://example.com" } }
```

- **Response Body**:
```json
{
  "action": "allow",
  "reason": "File read successfully",
  "result": "SAFE_REPORT_d32bb527064469b46ef0d280"
}
```

## Security Policies

1. **`read_file` Sandbox**:
   - Allowed strictly inside `/srv/agent-redteam/sandbox-2c3b759c51`.
   - Blocks path traversal attempts (relative `..`, URL-encoded `%2e%2e`, double-encoded, null-byte injection).
   - Allows safe benign files containing `..` or `%2e%2e` in literal names.
   - Prevents leaking the canary content `AGENT_GUARDRAIL_CANARY_8723dc9879f936b54bd645df85fbdf8235a2889d`.

2. **`fetch_url` SSRF Protection**:
   - Only exact hostnames allowed: `example.com` and `www.iana.org`.
   - Blocks private, loopback (`127.0.0.1`), link-local (`169.254.169.254`), metadata, userinfo-confused, lookalike hosts, and redirect-to-private attempts.

## Running Tests

```bash
python -m unittest test_guardrail.py
```
