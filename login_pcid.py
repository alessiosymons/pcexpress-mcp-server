#!/usr/bin/env python3
"""One-time PCID login helper for the PC Express MCP server.

Run this on a machine with a browser. It performs the PC Express app's OAuth2
Authorization Code + PKCE flow against PC ID, captures a refresh token, and prints
the environment variables to set on the (headless) MCP server.

Because it uses your real browser for the login step, it is not subject to the
bot-detection that blocks scripted logins. The refresh token it produces lets the
server mint access tokens on its own from then on.

Usage:
    PCEXPRESS_CLIENT_SECRET=<secret> python login_pcid.py

The client secret is a fixed app value; see README / AUTH_NOTES.md for how it was obtained.
"""

import base64
import contextlib
import hashlib
import secrets
import sys
import urllib.parse
import webbrowser

import requests

import pcid_config as cfg


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_authorize_url(code_challenge: str, state: str, nonce: str) -> str:
    params = {
        "client_id": cfg.CLIENT_ID,
        "response_type": "code",
        "scope": cfg.SCOPE,
        "redirect_uri": cfg.REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": nonce,
    }
    return cfg.AUTHORIZE_ENDPOINT + "?" + urllib.parse.urlencode(params)


def extract_code(redirect_input: str, expected_state: str) -> str:
    """Pull ?code= out of the pasted redirect URL (or accept a bare code)."""
    redirect_input = redirect_input.strip()
    if "code=" not in redirect_input:
        return redirect_input  # assume the user pasted the bare code
    q = urllib.parse.urlparse(redirect_input).query
    parsed = urllib.parse.parse_qs(q)
    if "error" in parsed:
        raise SystemExit(
            f"Authorization returned an error: {parsed.get('error')} {parsed.get('error_description')}"
        )
    state = parsed.get("state", [None])[0]
    if state and expected_state and state != expected_state:
        print("WARNING: state mismatch — proceed only if you trust this redirect.", file=sys.stderr)
    return parsed["code"][0]


def exchange_code(code: str, code_verifier: str) -> dict:
    if not cfg.CLIENT_SECRET:
        raise SystemExit("Set PCEXPRESS_CLIENT_SECRET before running.")
    base = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": cfg.CLIENT_ID,
        "client_secret": cfg.CLIENT_SECRET,
        "code_verifier": code_verifier,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "okhttp/4.12.0",
        **cfg.PCID_HEADERS,
    }
    # The app omits redirect_uri; some IDCS configs require it. Try app-exact first.
    for body in (base, {**base, "redirect_uri": cfg.REDIRECT_URI}):
        r = requests.post(cfg.TOKEN_ENDPOINT, data=body, headers=headers, timeout=30)
        if r.status_code == 200:
            return r.json()
        last = r
    raise SystemExit(f"Token exchange failed: HTTP {last.status_code} {last.text[:300]}")


def login_manual() -> dict:
    """Interactive browser-and-paste login. Returns the token response dict."""
    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    state = _b64url(secrets.token_bytes(24))
    nonce = _b64url(secrets.token_bytes(16))

    url = build_authorize_url(challenge, state, nonce)
    print("\n1) A browser window will open (or copy this URL into your browser):\n")
    print(url + "\n")
    print("2) Sign in with your PC id. When the page finishes, the browser will try to")
    print("   open a 'com.loblaw.pcx://...' link and show an error — that is expected.")
    print("   Copy the FULL address (starts with com.loblaw.pcx://) from the address bar.\n")
    with contextlib.suppress(Exception):
        webbrowser.open(url)

    redirect_input = input(
        "3) Paste the com.loblaw.pcx:// redirect URL (or just the code) here:\n> "
    )
    code = extract_code(redirect_input, state)
    return exchange_code(code, verifier)


def save_tokens(tokens: dict) -> str:
    """Seed the server's state file so the token never goes in an env var or config."""
    import json
    import os
    import time

    state_dir = os.getenv("PCEXPRESS_STATE_DIR", os.path.expanduser("~/.pcexpress-mcp"))
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    path = os.path.join(state_dir, "pcid_token_state.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(
            {
                "refresh_token": tokens["refresh_token"],
                "access_token": tokens.get("access_token"),
                "expires_at": time.time() + int(tokens.get("expires_in", 3600)),
            },
            f,
        )
    return path


def login_browser(timeout_s: int = 300) -> dict:
    """Open real Chrome on the PC id page; the user signs in, we catch the redirect.

    Credentials are typed into the PC id page by the user and never seen here.
    """
    from playwright.sync_api import sync_playwright

    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    state = _b64url(secrets.token_bytes(24))
    nonce = _b64url(secrets.token_bytes(16))

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome",
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        try:
            page = browser.new_context().new_page()
            page.goto(build_authorize_url(challenge, state, nonce))
            # PC id ends on .../login/success?redirectURL=com.loblaw.pcx://...?code=...
            page.wait_for_url("**/login/success**", timeout=timeout_s * 1000)
            q = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)
            inner = urllib.parse.unquote(q.get("redirectURL", [page.url])[0])
        finally:
            browser.close()
    return exchange_code(extract_code(inner, state), verifier)


def main():
    tokens = login_manual() if "--manual" in sys.argv else login_browser()
    refresh = tokens.get("refresh_token")
    if not refresh:
        raise SystemExit(
            f"No refresh_token in response (scope missing offline_access?): {list(tokens)}"
        )
    path = save_tokens(tokens)
    print(f"\n=== Success. Saved tokens to {path} (chmod 600). ===")
    print("The server refreshes automatically; no env var needed.")


if __name__ == "__main__":
    main()
