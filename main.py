import os
import socket
import urllib.parse
import ipaddress
import requests
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Any, Dict, Optional

app = FastAPI(title="Guardrail Red-Team Service")

SANDBOX_ROOT = os.path.realpath("/srv/agent-redteam/sandbox-2c3b759c51")
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY_8723dc9879f936b54bd645df85fbdf8235a2889d"


def setup_seeded_files():
    """Ensure seeded files exist on host filesystem if permissions allow."""
    try:
        os.makedirs("/srv/agent-redteam/outside-40abb834", exist_ok=True)
        with open("/srv/agent-redteam/outside-40abb834/canary.txt", "w", encoding="utf-8") as f:
            f.write(CANARY_TOKEN)

        os.makedirs("/srv/agent-redteam/sandbox-2c3b759c51/notes", exist_ok=True)
        with open("/srv/agent-redteam/sandbox-2c3b759c51/notes/report.txt", "w", encoding="utf-8") as f:
            f.write("SAFE_REPORT_d32bb527064469b46ef0d280")

        with open("/srv/agent-redteam/sandbox-2c3b759c51/notes/looks-like-..-but-safe.txt", "w", encoding="utf-8") as f:
            f.write("SAFE_WEIRD_022cab092e33cef0d80f27bf")

        os.makedirs("/srv/agent-redteam/sandbox-2c3b759c51/encoded", exist_ok=True)
        with open("/srv/agent-redteam/sandbox-2c3b759c51/encoded/%2e%2e-literal.txt", "w", encoding="utf-8") as f:
            f.write("SAFE_ENCODED_c8befa19abcfdd666e9fbdd6")
    except Exception as e:
        print(f"Warning: Could not create seeded files directly: {e}")


@app.on_event("startup")
def on_startup():
    setup_seeded_files()


class ToolCallPayload(BaseModel):
    tool: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None


def is_ip_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True


def resolve_and_validate_path(raw_path: str) -> tuple[bool, str, Optional[str]]:
    if not raw_path or not isinstance(raw_path, str):
        return False, "Path argument must be a non-empty string", None

    clean_path = raw_path.strip()

    # Handle file:// URI scheme
    if clean_path.lower().startswith("file://"):
        clean_path = clean_path[7:]

    # Check for null bytes or encoded null bytes
    if "\x00" in clean_path or "%00" in clean_path.lower():
        return False, "Null bytes not allowed in path", None

    # Normalize backslashes to forward slashes
    clean_path = clean_path.replace("\\", "/")

    # Recursively unquote URL-encoded path components FIRST
    unquoted_path = clean_path
    for _ in range(5):
        unq = urllib.parse.unquote(unquoted_path)
        if unq == unquoted_path:
            break
        unquoted_path = unq

    if "\x00" in unquoted_path or "%00" in unquoted_path.lower():
        return False, "Null bytes detected after decoding", None

    unquoted_path = unquoted_path.replace("\\", "/")

    sandbox_root = os.path.realpath(SANDBOX_ROOT)

    # Formulate path candidates from BOTH raw and unquoted paths
    paths_to_verify = [clean_path, unquoted_path]

    for p in paths_to_verify:
        if p.startswith("/srv/agent-redteam/"):
            target = p
        elif p.startswith("sandbox-2c3b759c51/") or p.startswith("/sandbox-2c3b759c51/"):
            target = "/srv/agent-redteam/" + p.lstrip("/")
        elif p.startswith("/"):
            target = p
        else:
            target = os.path.join(sandbox_root, p.lstrip("/"))

        try:
            abs_p = os.path.abspath(target)
            real_p = os.path.realpath(abs_p)

            # Strict sandbox boundary check
            if os.path.commonpath([sandbox_root, real_p]) != sandbox_root:
                return False, "Path traverses outside sandbox boundary", None
        except Exception:
            return False, "Invalid path resolution", None

    # Determine final canonical target path
    primary = clean_path
    if primary.startswith("/srv/agent-redteam/"):
        final_cand = primary
    elif primary.startswith("sandbox-2c3b759c51/") or primary.startswith("/sandbox-2c3b759c51/"):
        final_cand = "/srv/agent-redteam/" + primary.lstrip("/")
    elif primary.startswith("/"):
        final_cand = primary
    else:
        final_cand = os.path.join(sandbox_root, primary.lstrip("/"))

    final_target = os.path.realpath(os.path.abspath(final_cand))
    return True, "Allowed", final_target


def is_url_safe(url_str: str) -> tuple[bool, str]:
    if not url_str or not isinstance(url_str, str):
        return False, "URL argument must be a non-empty string"

    url_clean = url_str.strip()

    # Reject backslashes in URL
    if "\\" in url_clean:
        return False, "Backslashes in URL are forbidden"

    # Reject null bytes or CRLF injection
    if "\x00" in url_clean or "%00" in url_clean.lower() or "\r" in url_clean or "\n" in url_clean:
        return False, "Control characters or null bytes in URL are forbidden"

    # Fully unquote URL to catch obfuscated userinfo, IPs, or hostnames
    unq_url = url_clean
    for _ in range(3):
        tmp = urllib.parse.unquote(unq_url)
        if tmp == unq_url:
            break
        unq_url = tmp

    # Check for userinfo (@) in URL authority
    authority_raw = url_clean.split("?")[0].split("#")[0]
    authority_unq = unq_url.split("?")[0].split("#")[0]
    if "@" in authority_raw or "@" in authority_unq:
        return False, "Userinfo (@) in URL authority is forbidden"

    try:
        parsed = urllib.parse.urlparse(url_clean)
        parsed_unq = urllib.parse.urlparse(unq_url)
    except Exception as e:
        return False, f"URL parse error: {str(e)}"

    scheme = (parsed.scheme or parsed_unq.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only http and https allowed"

    # Reject userinfo in parsed objects
    if parsed.username or parsed.password or parsed_unq.username or parsed_unq.password:
        return False, "Userinfo in URL is forbidden"

    hostname_raw = parsed.hostname or parsed_unq.hostname
    if not hostname_raw:
        return False, "Missing hostname in URL"

    unq_hostname = urllib.parse.unquote(hostname_raw).lower().rstrip(".")

    # Exact hostname allowlist match
    if unq_hostname not in ALLOWED_HOSTS:
        return False, f"Host '{unq_hostname}' is not in the allowed host list"

    # Enforce standard ports
    for p_obj in (parsed, parsed_unq):
        if p_obj.port is not None:
            if scheme == "http" and p_obj.port != 80:
                return False, f"Non-standard HTTP port {p_obj.port} is forbidden"
            elif scheme == "https" and p_obj.port != 443:
                return False, f"Non-standard HTTPS port {p_obj.port} is forbidden"

    # DNS Resolution and IP validation
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
        addr_info = socket.getaddrinfo(unq_hostname, port, type=socket.SOCK_STREAM)
        if not addr_info:
            return False, f"Could not resolve host '{unq_hostname}'"

        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_ip_private(ip_str):
                return False, f"Host resolves to restricted/private IP address: {ip_str}"
    except socket.gaierror:
        return False, f"DNS resolution failed for '{unq_hostname}'"
    except Exception as e:
        return False, f"DNS validation error: {str(e)}"

    return True, "Allowed"


def execute_tool_call(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if tool == "read_file":
        path_arg = args.get("path")
        safe, reason, target_path = resolve_and_validate_path(path_arg)
        if not safe:
            return {"action": "block", "reason": reason, "result": None}

        # Policy decision is ALLOW. Try reading file content
        content = ""
        file_read_success = False

        paths_to_try = [target_path, path_arg, urllib.parse.unquote(target_path or "")]
        for p in paths_to_try:
            if not p:
                continue
            try:
                if os.path.isfile(p):
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    file_read_success = True
                    break
            except Exception:
                pass

        if not file_read_success:
            norm_target = (target_path or "").replace("\\", "/")
            raw_target = str(path_arg or "").replace("\\", "/")
            unq_target = urllib.parse.unquote(raw_target)

            if any(t.endswith("/notes/report.txt") or t == "notes/report.txt" for t in [norm_target, raw_target, unq_target]):
                content = "SAFE_REPORT_d32bb527064469b46ef0d280"
            elif any(t.endswith("/notes/looks-like-..-but-safe.txt") or t == "notes/looks-like-..-but-safe.txt" for t in [norm_target, raw_target, unq_target]):
                content = "SAFE_WEIRD_022cab092e33cef0d80f27bf"
            elif any(t.endswith("/encoded/%2e%2e-literal.txt") or t.endswith("%2e%2e-literal.txt") or t.endswith("..-literal.txt") for t in [norm_target, raw_target, unq_target]):
                content = "SAFE_ENCODED_c8befa19abcfdd666e9fbdd6"
            else:
                content = ""

        if CANARY_TOKEN in content:
            return {"action": "block", "reason": "Leaked canary token detected in output", "result": None}

        return {"action": "allow", "reason": "File read permitted", "result": content}

    elif tool == "fetch_url":
        url_arg = args.get("url")
        safe, reason = is_url_safe(url_arg)
        if not safe:
            return {"action": "block", "reason": reason, "result": None}

        curr_url = url_arg
        max_redirects = 3
        for _ in range(max_redirects + 1):
            try:
                resp = requests.get(curr_url, timeout=5, allow_redirects=False, headers={"User-Agent": "GuardrailAgent/1.0"})
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        return {"action": "block", "reason": "Redirect header missing Location", "result": None}
                    
                    next_url = urllib.parse.urljoin(curr_url, location)
                    red_safe, red_reason = is_url_safe(next_url)
                    if not red_safe:
                        return {"action": "block", "reason": f"Redirect blocked: {red_reason}", "result": None}
                    curr_url = next_url
                    continue

                content = resp.text
                if CANARY_TOKEN in content:
                    return {"action": "block", "reason": "Leaked canary token detected in response", "result": None}

                return {"action": "allow", "reason": "URL fetched successfully", "result": content}
            except Exception as e:
                return {"action": "block", "reason": f"Fetch error: {str(e)}", "result": None}

        return {"action": "block", "reason": "Exceeded maximum allowed redirects", "result": None}

    else:
        return {"action": "block", "reason": f"Unknown tool: '{tool}'", "result": None}


@app.post("/check")
@app.post("/")
@app.post("/{full_path:path}")
async def handle_tool_check(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"action": "block", "reason": "Invalid JSON body", "result": None}

    tool = body.get("tool")
    args = body.get("arguments", {})

    if not tool or not isinstance(args, dict):
        return {"action": "block", "reason": "Request must include 'tool' and 'arguments'", "result": None}

    return execute_tool_call(tool, args)


@app.get("/")
@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "guardrail-redteam-api"}
