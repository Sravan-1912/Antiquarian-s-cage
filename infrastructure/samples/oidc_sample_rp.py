"""Minimal OIDC relying party for verifying Antiquarian's Cage SSO end to end (development only).

    set CAGE_ISSUER=http://localhost:5173/api/v1/oidc
    set CAGE_CLIENT_ID=cage-...   &   set CAGE_CLIENT_SECRET=...
    python infrastructure/samples/oidc_sample_rp.py        → http://localhost:8090

Implements the full authorization-code + PKCE flow: state and nonce checks, server-side code exchange with client
secret, ID-token signature verification against the published JWKS (issuer, audience, expiry, nonce), and a
userinfo call. Requires PyJWT[crypto] (present in the backend virtualenv).
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt

ISSUER = os.environ.get("CAGE_ISSUER", "http://localhost:5173/api/v1/oidc")
CLIENT_ID = os.environ["CAGE_CLIENT_ID"]
CLIENT_SECRET = os.environ["CAGE_CLIENT_SECRET"]
REDIRECT = "http://localhost:8090/callback"
PENDING: dict[str, dict] = {}  # state → {verifier, nonce}


def _get(url: str, headers: dict | None = None) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10) as r:
        return json.loads(r.read())


DISCOVERY = _get(ISSUER + "/.well-known/openid-configuration")


def page(body: str) -> bytes:
    return (f"<!doctype html><meta charset=utf-8><title>Sample app</title><body style='font:14px system-ui;"
            f"background:#f4f4f5;max-width:760px;margin:40px auto'>{body}</body>").encode()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, headers: dict | None = None):
        self.send_response(code)
        for k, v in (headers or {"Content-Type": "text/html; charset=utf-8"}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        if url.path == "/":
            return self._send(200, page("<h2>Sample Wiki (relying party)</h2><p>This app trusts Antiquarian's Cage for sign-in.</p>"
                                        "<p><a href='/login'>Sign in with Antiquarian's Cage</a></p>"))
        if url.path == "/login":
            state, nonce, verifier = secrets.token_urlsafe(16), secrets.token_urlsafe(16), secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            PENDING[state] = {"verifier": verifier, "nonce": nonce}
            params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
                      "scope": "openid email profile", "state": state, "nonce": nonce, "code_challenge": challenge,
                      "code_challenge_method": "S256"}
            return self._send(302, b"", {"Location": DISCOVERY["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)})
        if url.path == "/callback":
            if "error" in q:
                return self._send(200, page(f"<h2>Sign-in refused</h2><pre>{html.escape(json.dumps(q, indent=2))}</pre>"))
            st = PENDING.pop(q.get("state", [""])[0], None)
            if st is None:
                return self._send(400, page("<h2>Invalid state</h2>"))
            data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": q["code"][0],
                                           "redirect_uri": REDIRECT, "code_verifier": st["verifier"]}).encode()
            basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            req = urllib.request.Request(DISCOVERY["token_endpoint"], data=data, headers={
                "Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    tokens = json.loads(r.read())
            except urllib.error.HTTPError as e:
                return self._send(200, page(f"<h2>Token exchange failed</h2><pre>{html.escape(e.read().decode())}</pre>"))
            jwk = jwt.PyJWKClient(DISCOVERY["jwks_uri"]).get_signing_key_from_jwt(tokens["id_token"])
            claims = jwt.decode(tokens["id_token"], jwk.key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER)
            if claims.get("nonce") != st["nonce"]:
                return self._send(400, page("<h2>Nonce mismatch</h2>"))
            info = _get(DISCOVERY["userinfo_endpoint"], {"Authorization": f"Bearer {tokens['access_token']}"})
            return self._send(200, page(
                f"<h2>Signed in as {html.escape(claims.get('name', ''))}</h2>"
                "<p>✔ state ✔ PKCE ✔ code exchange ✔ ID-token signature (JWKS) ✔ issuer/audience/expiry ✔ nonce ✔ userinfo</p>"
                f"<h3>ID token claims</h3><pre>{html.escape(json.dumps(claims, indent=2))}</pre>"
                f"<h3>Userinfo</h3><pre>{html.escape(json.dumps(info, indent=2))}</pre>"))
        return self._send(404, page("not found"))

    def log_message(self, fmt, *args):
        print("rp:", fmt % args)


if __name__ == "__main__":
    print(f"Sample RP on http://localhost:8090 (issuer {ISSUER})")
    HTTPServer(("127.0.0.1", 8090), Handler).serve_forever()
