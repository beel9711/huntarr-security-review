# Huntarr.io Heavy Code + Security Review

- Repository: `https://github.com/plexguide/Huntarr.io`
- Commit reviewed: `fa475ab6` (2026-02-23)
- Review date: 2026-02-23
- Method: Manual code review + automated static analysis tools

## Scope and Method

Manual code review covering auth/session management, sensitive routes, command execution, input parsing, crypto, and Windows service behavior. Supplemented with automated static analysis (`bandit`) and dependency vulnerability scanning (`pip-audit`). Also reviewed Docker hardening, CI workflow hardening, dependency governance, and disclosure/release hygiene.

Artifacts generated during analysis:
- `bandit-src.json`
- `bandit-root-dist.json`
- `pip-audit.json`

## Executive Summary

The codebase has multiple critical authentication and authorization flaws that allow unauthenticated remote state changes, account takeover, and credential exfiltration. 21 findings total across critical (7), high (6), medium (5), and OSS best-practice (2) severity levels (plus 1 high that aggravates an existing critical).

The most severe issue is an unauthenticated settings write endpoint that returns full settings -- not just its own config, but API keys and credentials for every integrated *arr application (Sonarr, Radarr, Prowlarr, etc.) in cleartext. Beyond the original findings, additional review revealed that unauthenticated callers can also re-arm the setup flow to create a new owner account, enroll their own 2FA on the owner account, generate recovery keys by sending a client-controlled `setup_mode` flag, and exploit a Zip Slip vulnerability in backup upload for arbitrary file write. The auth bypass whitelist in `auth.py` uses overly broad substring and suffix matching that exempts more endpoints than intended.

## Severity-Ranked Findings

## Critical

### 1) Unauthenticated write access to global settings, plus full settings disclosure in response

- Evidence:
`src/primary/auth.py:525` bypasses auth for `.../api/settings/general`.
`src/primary/web_server.py:717` defines `POST /api/settings/general` with no in-route auth guard.
`src/primary/web_server.py:845` returns `settings_manager.get_all_settings()`.
`src/primary/settings_manager.py:349` returns all app settings without secret redaction.

- Impact:
Any unauthenticated remote caller can modify security-sensitive settings and receive full settings data in the response, including API keys and proxy credentials.

- Exploit path:
`POST /api/settings/general` with JSON payload.
Examples: set `proxy_auth_bypass`, alter integration credentials, or exfiltrate full config by sending minimal payload and reading response.

- Remediation:
Require authenticated owner session for this endpoint except strictly gated setup state.
Do not include secrets in any API response by default.
Split setup-only settings from runtime admin settings.

### 2) Unauthenticated Plex account linking via client-controlled `setup_mode` (account takeover path)

- Evidence:
`src/primary/auth.py:525` bypasses auth for all `/api/auth/plex*`.
`src/primary/routes/plex_auth_routes.py:315` route `POST /api/auth/plex/link`.
`src/primary/routes/plex_auth_routes.py:326` trusts client `setup_mode` flag.
`src/primary/routes/plex_auth_routes.py:337` pulls username from first local user in setup mode.
`src/primary/routes/plex_auth_routes.py:397` links Plex token to that user.

- Impact:
Unauthenticated attacker can set `setup_mode=true`, link attacker-owned Plex token to local account, then authenticate as that account via Plex login flow.

- Remediation:
Never trust client `setup_mode`.
Authorize by validated session only, or require server-side setup-state check + one-time setup nonce.
Remove global auth bypass for `/api/auth/plex/*` and selectively allow only truly public endpoints.

### 3) Unauthenticated Plex unlink endpoint

- Evidence:
`src/primary/auth.py:525` bypasses auth for `/api/auth/plex*`.
`src/primary/routes/plex_auth_routes.py:427` route `POST /api/auth/plex/unlink` has no auth check.
`src/primary/auth.py:1189` `unlink_plex_from_user` defaults to first user context when username absent.

- Impact:
Unauthenticated caller can alter owner account linkage state (integrity/availability impact).

- Remediation:
Require authenticated session and verify caller identity before unlink.
Reject operation unless explicit authenticated username is provided and matches session principal.

### 4) Unauthenticated 2FA enrollment on owner account via whitelisted endpoints

- Evidence:
`src/primary/auth.py:525` bypass list contains `'/api/user/2fa/' in request.path` (substring match, not prefix).
`src/primary/routes/common.py:794` route `POST /api/user/2fa/setup` returns TOTP secret and QR code.
`src/primary/routes/common.py:805-807` falls back to `db.get_first_user()` when no session exists.
`src/primary/routes/common.py:850` route `POST /api/user/2fa/verify` enables 2FA using attacker-supplied code.
`src/primary/routes/common.py:861-863` same fallback to first user.

- Impact:
Unauthenticated attacker calls `/api/user/2fa/setup` to receive the TOTP secret for the owner account, generates a valid code, then calls `/api/user/2fa/verify` to enable 2FA with their own authenticator. The attacker now controls the second factor on the owner's account. This is a complete account takeover path independent of password knowledge.

- Exploit path:
`POST /api/user/2fa/setup` (no auth) → receive `secret` → generate TOTP code → `POST /api/user/2fa/verify` with `{"code": "<attacker_code>"}` → 2FA enabled with attacker's secret.

- Remediation:
Remove `/api/user/2fa/` from the auth bypass whitelist. These endpoints must require an authenticated session. The substring match (`in request.path`) is also overly broad and should be replaced with explicit route checks.

### 5) Unauthenticated recovery key generation via client-controlled `setup_mode`

- Evidence:
`src/primary/auth.py:525` bypass list covers `request.path.startswith('/auth/recovery-key')`.
`src/primary/routes/common.py:948` route `POST /auth/recovery-key/generate`.
`src/primary/routes/common.py:959` trusts `setup_mode` from client request body.
`src/primary/routes/common.py:987` skips password verification when `setup_mode` is true.
`src/primary/routes/common.py:1012` generates and returns a valid recovery key.

- Impact:
Unauthenticated attacker sends `{"setup_mode": true}` to generate a valid recovery key for the owner account without knowing the password. The recovery key can then be used to reset the password and take over the account.

- Exploit path:
`POST /auth/recovery-key/generate` with `{"setup_mode": true}` → receive `recovery_key` → use at `/auth/recovery-key/reset` to set new password.

- Remediation:
Never trust client-supplied `setup_mode`. Gate on server-side setup state only. Require authenticated session or verified password before generating recovery keys.

### 6) Zip Slip arbitrary file write via backup upload

- Evidence:
`src/routes/backup_routes.py:867-868` calls `zipf.extractall(str(temp_dir))` on user-uploaded ZIP.
Python's `zipfile.extractall()` does not sanitize filenames containing `../` sequences.
Container runs as root (PUID=0, PGID=0) by default.

- Impact:
Attacker uploads a crafted ZIP with path traversal entries (e.g., `../../../etc/cron.d/backdoor`). Files are written outside the temp directory as root. This is arbitrary file write inside the container and can lead to code execution.

- Exploit path:
Requires authenticated session or bypass mode. Combined with finding #1 (enable `local_access_bypass` + spoof header), this is reachable from an unauthenticated attacker.

- Remediation:
Validate all filenames from ZIP entries. Reject any entry containing `..` or absolute paths. Use `zipfile.Path` or manual sanitization before extraction. Consider using `shutil.unpack_archive` with a restricted filter.

### 7) Unauthenticated setup clear re-arms account creation (full account takeover)

- Evidence:
`scripts/prove_vulns.py:108` calls `POST /api/setup/clear` with an anonymous opener (no session cookie, no auth header) and succeeds.
`src/primary/auth.py:525` bypass list covers `/api/setup/*` routes.
The prove script depends on this call returning 2xx to an unauthenticated caller.

- Impact:
Any unauthenticated caller can `POST /api/setup/clear` at any time after initial setup to re-arm the setup flow. The attacker then navigates to the setup page and creates a new owner account, fully replacing the legitimate owner's credentials. This is a complete account takeover that requires zero prior access and is independent of all other findings.

- Exploit path:
`POST /api/setup/clear` (no auth) → setup mode re-armed → `POST /setup` with attacker-chosen credentials → attacker is now the owner.

- Remediation:
Remove `/api/setup/clear` from the auth bypass whitelist. This endpoint must require an authenticated owner session. Setup re-arm should additionally require a confirmation step or be disabled entirely after initial setup.

## High

### 8) Local access bypass trusts spoofable `X-Forwarded-For`

- Evidence:
`src/primary/auth.py:603` reads `X-Forwarded-For` directly.
`src/primary/auth.py:610` treats first forwarded IP as trusted local indicator.
`src/primary/auth.py:621` grants bypass session when considered local.

- Impact:
If `local_access_bypass` is enabled, remote clients can spoof `X-Forwarded-For` (e.g., `127.0.0.1`) and bypass login.

- Remediation:
Trust forwarded headers only from known reverse proxies.
Use strict proxy trust config and parse chain safely.
If direct exposure is possible, ignore `X-Forwarded-For` completely.

### 9) Windows service/install scripts grant `Everyone:(OI)(CI)F` recursively

- Evidence:
`distribution/windows/resources/windows_service.py:287` and `distribution/windows/resources/windows_service.py:293`.
`distribution/windows/scripts/windows_setup.py:97`.
`distribution/windows/scripts/configure_paths.py:90`.

- Impact:
World-writable config/executable paths can enable local privilege escalation and tampering, especially when service runs with elevated rights.

- Remediation:
Replace `Everyone:F` with least-privilege ACLs (service account + Administrators as needed).
Avoid recursive full-control grants on executable directories.

### 10) Hardcoded external credentials/keys in source

- Evidence:
`src/primary/apps/media_hunt/metadata_refresh.py:32` hardcoded TMDB API key.
`src/primary/apps/movie_hunt/list_fetchers.py:15` same TMDB key.
`src/primary/apps/tv_hunt/list_fetchers.py:14` same TMDB key.
`src/primary/routes/media_hunt/discovery_tv.py:28` same TMDB key.
`src/primary/routes/media_hunt/import_lists_movie.py:474` hardcoded Trakt client id.
`src/primary/routes/media_hunt/import_lists_movie.py:478` hardcoded Trakt client secret.
`src/primary/routes/media_hunt/import_lists_tv.py:501` and `src/primary/routes/media_hunt/import_lists_tv.py:505` same credentials.

- Impact:
Credential leakage, key abuse, quota exhaustion, and forced key rotation risk.

- Remediation:
Move all keys/secrets to environment or secret manager only.
Rotate exposed keys/secrets.
Add pre-commit and CI secret scanning.

### 11) Full cross-app credential exposure in settings response

- Evidence:
`proof-results.json` shows the response to `POST /api/settings/general` returns configuration for all integrated apps: Sonarr, Radarr, Prowlarr, Lidarr, Readarr, Whisparr, and others -- not just the `general` section that was written.
`src/primary/web_server.py:845` returns `settings_manager.get_all_settings()`.
`src/primary/settings_manager.py:349` returns all app settings without section filtering or secret redaction.

- Impact:
Writing a single innocuous key (e.g., `{"timezone": "UTC"}`) to the unauthenticated settings endpoint returns API keys, instance URLs, and credentials for every configured downstream application (Sonarr, Radarr, Prowlarr, etc.). This means a single unauthenticated call exfiltrates not just Huntarr's own secrets but direct API access credentials for every *arr application it manages. This aggravates finding #1 significantly.

- Exploit path:
`POST /api/settings/general` with `{"timezone": "UTC"}` (no auth) → response body contains `sonarr.instances[].api_key`, `radarr.instances[].api_key`, `prowlarr.api_key`, and all integration credentials.

- Remediation:
Return only the section that was written, not the entire settings tree. Never include API keys or credentials in API responses. If full settings are needed for a UI, require authenticated session and redact all secret fields.

### 12) Path traversal in backup restore and delete operations

- Evidence:
`src/routes/backup_routes.py:316` uses `self.backup_dir / backup_id` where `backup_id` comes from request JSON.
`src/routes/backup_routes.py:418` same pattern for delete.
`src/routes/backup_routes.py:491` calls `shutil.rmtree(backup_folder)` on the constructed path.
No validation for `..` or path separator characters in `backup_id`.

- Impact:
Attacker supplies `backup_id: "../../"` to delete arbitrary directories. The `shutil.rmtree` call makes this a recursive directory deletion primitive. For restore, path traversal allows reading/replacing database files outside the backup directory.

- Remediation:
Validate `backup_id` against a strict allowlist pattern (alphanumeric, underscore, dash, dot only). Reject any value containing path separators or `..`. Resolve the final path and verify it is still under `backup_dir`.

### 13) Auth bypass whitelist uses overly broad matching patterns

- Evidence:
`src/primary/auth.py:525` uses `'/api/user/2fa/' in request.path` -- substring match, not prefix.
`src/primary/auth.py:517` uses `request.path.endswith('/setup')` and `request.path.endswith('/user')`.
`src/primary/auth.py:521` uses `request.path.endswith('/ping')`.

- Impact:
The substring match for 2FA bypasses auth for any URL containing that string anywhere in the path. The `endswith` patterns bypass auth for any route path ending in `/setup`, `/user`, or `/ping` -- including future routes that may be added under those suffixes. This is a latent vulnerability that becomes exploitable as routes are added.

- Remediation:
Replace all substring and suffix matches with explicit route path checks or a maintained allowlist of exact paths. Use Flask's `url_rule` matching rather than raw string operations on `request.path`.

## Medium

### 14) Password hashing uses salted SHA-256 instead of memory-hard KDF

- Evidence:
`src/primary/auth.py:158` and `src/primary/auth.py:161`.

- Impact:
If password database is leaked, offline cracking cost is much lower than with Argon2id/scrypt/bcrypt.

- Remediation:
Use Argon2id or bcrypt for new hashes.
Migrate on login for existing hashes.

### 15) Recovery key entropy is low and rate-limit keying trusts spoofable forwarded IP

- Evidence:
`src/primary/utils/db_mixins/db_requestarr.py:379-397` recovery key space is small human-word format + 2 digits.
`src/primary/routes/common.py:1034` and `src/primary/routes/common.py:1099` use forwarded IP directly for rate-limiting identity.

- Impact:
Online brute force resistance is weaker than expected and can be bypassed/distributed by header spoofing.

- Remediation:
Increase key entropy substantially (long random base32/base58 token).
Bind rate limit to trusted network metadata, not raw client header.
Add account-level throttle in addition to IP-based controls.

### 16) Network calls without explicit timeouts

- Evidence:
`src/primary/auth.py:961`, `src/primary/auth.py:1039`, `src/primary/auth.py:1078`.
`src/primary/routes/plex_auth_routes.py:121`, `src/primary/routes/plex_auth_routes.py:178`, `src/primary/routes/plex_auth_routes.py:365`.

- Impact:
Potential request hangs, thread starvation, and user-visible DoS under network degradation.

- Remediation:
Set explicit connect/read timeouts for all outbound HTTP calls.

### 17) XML parsing of untrusted data uses stdlib `ElementTree.fromstring`

- Evidence:
`src/primary/apps/media_hunt/rss_sync.py:66`.
`src/primary/apps/movie_hunt/list_fetchers.py:553`.
`src/primary/apps/nzb_hunt/nzb_parser.py:83`.
`src/primary/routes/media_hunt/discovery_movie.py:134`.
`src/primary/routes/media_hunt/discovery_tv.py:204`.
`src/primary/routes/media_hunt/indexers.py:231`.

- Impact:
Potential XML-based DoS vectors depending on parser behavior and payload size.

- Remediation:
Use `defusedxml` wrappers for untrusted XML.
Enforce payload size limits pre-parse.

### 18) Dependency vulnerability: Flask 3.1.2

- Evidence:
`pip-audit` result in `pip-audit.json` reports:
`flask==3.1.2` -> `CVE-2026-27205` (fix `3.1.3`, alias `GHSA-68rp-wp8r-4726`).

- Impact:
Cache behavior vulnerability under specific cache/session access patterns.

- Remediation:
Upgrade to `Flask>=3.1.3`.

## OSS Best-Practice Findings

### 19) CI/CD action pinning and governance gaps

- Evidence:
Workflow actions are pinned to major tags rather than immutable SHAs.
Examples: `actions/checkout@v4`, `docker/build-push-action@v5`, `softprops/action-gh-release@v1`.
No `SECURITY.md`, no `dependabot.yml` found.

- Impact:
Higher supply-chain risk from upstream action tag movement and slower vuln response cadence.

- Remediation:
Pin GitHub Actions to commit SHAs.
Add `dependabot.yml` for dependencies and action updates.
Add `SECURITY.md` with disclosure process and patch SLAs.

### 20) Container hardening defaults to root

- Evidence:
`Dockerfile` sets `ENV PUID=0` and `ENV PGID=0` by default.
No Docker `USER` directive in final runtime stage.

- Impact:
Higher blast radius for container breakout or app compromise.

- Remediation:
Default to non-root runtime UID/GID.
Use root only for explicit compatibility mode.

## Automated Scan Summary

### Bandit

- Scope: `src/`, `main.py`, `distribution/`
- Results:
`bandit-src.json`: 340 findings (`HIGH:5`, `MEDIUM:41`, `LOW:294`)
`bandit-root-dist.json`: 25 findings (`HIGH:2`, `MEDIUM:6`, `LOW:17`)

Most low findings were repetitive (`B110` try/except/pass) and not all are direct exploitable vulnerabilities. Highest-signal issues are reflected in the findings above.

### pip-audit

- Scope: `requirements.txt`
- Results: 1 known vulnerability (`flask==3.1.2`, `CVE-2026-27205`, fixed in `3.1.3`)

## Notes on Potential False Positives

- Several `bandit` SQL-construction alerts are currently constrained by allow-lists and parameter binding patterns.
- These are lower risk in present form, but future modifications could turn them into exploitable injection points; keep strict allow-lists and avoid direct string interpolation for SQL structure whenever possible.
