#!/usr/bin/env python3
"""
basic_oidc_scanner.py — Passive/active auditor for public OIDC discovery documents,
completely unauthenticated.

Fetches and parses an OpenID Connect discovery document
(.well-known/openid-configuration), checks it for common misconfigurations and
risky settings, analyzes the referenced JWKS, inspects the issuer's TLS, and
(optionally) probes the other advertised endpoints for low-risk issues.

Request tiers
-------------
* DEFAULT (passive-ish): GET the discovery document, GET the JWKS (opt out with
  --no-jwks), and one TLS handshake to the issuer host for cert/protocol detail.
  Nothing is written to the target.
* --probe: additionally GET the other advertised endpoints and the
  WebFinger endpoint. Read-only, non-destructive.
* --dynamic-reg-probe: the only option that sends a POST (a minimal Dynamic
  Client Registration attempt). OFF by default, requires --probe.

Discovery fallbacks: if openid-configuration is absent, the tool also tries the
RFC 8414 oauth-authorization-server locations.

Each finding reports: where (JSON pointer + source document), the offending
evidence, the Impact, and a Recommendation. Findings that can only indicate a
*surface* (exploitability must be confirmed with real tokens / live flows) are
tagged "manual verification required".

Requires: requests  (pip install requests)
Optional: cryptography  (pip install cryptography) — enables x5c certificate
          checks in the JWKS and certificate-expiry checks with -k.
"""

import argparse
import base64
import hashlib
import io
import json
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote

__version__ = "1.3.0"

try:
    import requests
    import urllib3
except ImportError:
    sys.stderr.write("This script needs 'requests'.  pip install requests\n")
    sys.exit(2)

try:  # optional: x5c parsing and cert expiry on unverified handshakes
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa
    from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# --------------------------------------------------------------------------- #
# Finding model / severities
# --------------------------------------------------------------------------- #

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

COLORS = {
    "CRITICAL": "\033[1;37;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
    "OK": "\033[1;32m",
    "MANUAL": "\033[0;35m",
    "LABEL": "\033[1;34m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}

# Impact / Recommendation catalog, keyed by finding code. Kept centrally so the
# wording stays consistent and the check functions stay readable. Operational
# and purely-informational codes are intentionally absent (no I/R shown).
CATALOG = {
    "issuer-missing": (
        "Clients cannot validate the 'iss' claim, enabling token-substitution / "
        "IdP mix-up attacks.",
        "Serve a correct 'issuer' value that matches the discovery location."),
    "issuer-not-https": (
        "Discovery and token traffic can be intercepted or tampered with (MITM).",
        "Serve the issuer and all endpoints exclusively over HTTPS."),
    "issuer-url-mismatch": (
        "Relying parties that pin 'iss' may reject tokens, or — if lax — accept "
        "tokens from the wrong issuer (mix-up).",
        "Make 'issuer' exactly equal the origin+path the document is served from."),
    "issuer-has-query": (
        "Non-canonical issuer values break strict 'iss' comparison across RPs.",
        "Use a bare https origin (+path) with no query or fragment as the issuer."),
    "endpoint-not-https": (
        "Credentials, codes, or tokens on this endpoint can be intercepted.",
        "Serve the endpoint over HTTPS only."),
    "endpoint-off-issuer-host": (
        "Expands the trust boundary; a compromise or takeover of the other host "
        "affects the auth flow.",
        "Confirm the host is operated/trusted by the IdP, or move it on-issuer."),
    "alg-none": (
        "An attacker can forge a token with no signature and have it accepted, "
        "bypassing authentication entirely.",
        "Remove 'none' from the supported signing algorithms and reject it at "
        "the verifier."),
    "alg-confusion-surface": (
        "If the verifier selects the algorithm from the token header, an RS256->"
        "HS256 confusion attack can forge tokens using the public key as the "
        "HMAC secret.",
        "Pin the expected algorithm server-side; do not trust the token 'alg' "
        "header. Avoid advertising HS* alongside RS/ES/PS."),
    "pkce-not-advertised": (
        "Authorization codes may be interceptable (esp. public/mobile clients) "
        "without PKCE protection.",
        "Support and require PKCE 'S256' for authorization-code flows."),
    "pkce-plain": (
        "'plain' PKCE offers no protection if the challenge is observed.",
        "Support 'S256' only and reject 'plain'."),
    "pkce-no-s256": (
        "Code-interception protection is weak or absent without S256.",
        "Add 'S256' to code_challenge_methods_supported and require it."),
    "grant-implicit": (
        "Access tokens are returned in the URL fragment — exposed via browser "
        "history, Referer, and logs. Deprecated and removed in OAuth 2.1.",
        "Disable the implicit grant; use authorization code + PKCE."),
    "grant-password": (
        "ROPC hands the user's password to the client, defeating SSO/MFA and "
        "widening credential exposure. Deprecated.",
        "Disable the password grant; use a redirect-based code flow."),
    "grant-token-exchange": (
        "Token exchange enables delegation/impersonation; misconfiguration can "
        "allow privilege escalation across audiences.",
        "Restrict allowed actors, audiences, and scopes for token exchange."),
    "implicit-response-type": (
        "Tokens are delivered in the URL fragment (history/Referer/leak surface) "
        "and are prone to token-injection without nonce/at_hash validation.",
        "Disable implicit response types; use 'code' with PKCE."),
    "auth-method-none": (
        "Public clients (no authentication) widen abuse of the token endpoint; "
        "combined with weak redirect_uri checks this enables token theft.",
        "Require client authentication where possible; enforce PKCE for public "
        "clients and strict redirect_uri matching."),
    "request-uri-ssrf": (
        "The server may fetch an attacker-supplied request_uri, enabling SSRF "
        "and request-object injection.",
        "Set require_request_uri_registration=true (allowlist), or disable "
        "request_uri; validate and restrict outbound fetches."),
    "request-param": (
        "JWT request objects shift trust to signature/encryption handling, which "
        "is a common bypass point.",
        "Require signed request objects and verify alg/signature strictly."),
    "dynamic-registration": (
        "If registration is unauthenticated, anyone can create clients (e.g. with "
        "attacker redirect_uris), aiding phishing and token theft.",
        "Require authentication / an initial access token for registration; "
        "validate redirect_uris."),
    "scopes-no-openid": (
        "A provider that omits the 'openid' scope may not be a conformant OIDC "
        "provider; integrations may misbehave.",
        "Advertise 'openid' if OIDC is intended."),
    "jwks-malformed": (
        "Verifiers cannot load keys reliably, risking validation errors or unsafe "
        "fallbacks.",
        "Serve a well-formed JWKS with a 'keys' array."),
    "jwks-empty": (
        "No keys are published; signature verification cannot be performed from "
        "discovery.",
        "Publish the current public signing key(s) in the JWKS."),
    "jwks-private-key": (
        "Private/secret key material is publicly exposed — anyone can forge valid "
        "tokens. Full authentication bypass.",
        "Rotate the key immediately and publish ONLY public components "
        "(e.g. RSA n/e). Treat the exposed key as compromised."),
    "jwks-symmetric": (
        "A published symmetric (oct) key means the HMAC secret is public — anyone "
        "can forge valid HS* tokens.",
        "Never publish symmetric keys; use asymmetric signing (RS/ES/PS) for "
        "tokens RPs must verify, and rotate the exposed secret."),
    "jwks-weak-rsa": (
        "An undersized RSA key is more feasible to attack, weakening signature "
        "assurance.",
        "Use RSA >= 2048-bit (or EC P-256+) and rotate the weak key."),
    "jwks-no-kid": (
        "Without 'kid', verifiers may select the wrong key during rotation, "
        "causing outages or weakening validation.",
        "Assign a unique 'kid' to every key."),
    "jwks-key-alg-none": (
        "A key advertising alg 'none' invites unsigned-token acceptance.",
        "Remove 'none'; bind each key to a strong signing algorithm."),
    "jwks-dup-kid": (
        "Duplicate 'kid' values make key selection ambiguous and can undermine "
        "verification.",
        "Ensure every 'kid' is unique."),
    "jwks-malformed-key": (
        "Verifiers may fail to load the key or fall back to unsafe behavior.",
        "Publish complete, well-formed JWKs (RFC 7517/7518)."),
    "jwks-rsa-e1": (
        "With e=1 the 'signature' equals the message — anyone can forge tokens.",
        "Replace the key immediately; use e=65537."),
    "jwks-rsa-bad-e": (
        "An even exponent is not a valid RSA key; the key was generated or "
        "exported incorrectly.",
        "Regenerate the key with a standard library and e=65537."),
    "jwks-rsa-small-e": (
        "Small exponents (e.g. e=3) enable signature forgery against verifiers "
        "with lax PKCS#1 v1.5 padding checks (Bleichenbacher 2006).",
        "Use e=65537."),
    "jwks-rsa-factored": (
        "The private key can be derived from the public modulus — anyone can "
        "forge valid tokens.",
        "Treat the key as compromised: rotate it and fix the key generator."),
    "jwks-rsa-roca": (
        "Keys from vulnerable Infineon RSALib (ROCA) can have their private key "
        "recovered from the public modulus.",
        "Regenerate the key outside the affected hardware/firmware and rotate."),
    "jwks-ec-curve": (
        "Verifiers may reject the key, or the curve may be weak.",
        "Use P-256, P-384, P-521 (or Ed25519 for OKP)."),
    "jwks-ec-coord-length": (
        "Non-canonical encodings cause interoperability failures and can hint "
        "at a broken key export.",
        "Encode coordinates at the full fixed length for the curve."),
    "jwks-ec-off-curve": (
        "An invalid public point indicates a corrupted or malicious key; "
        "verifiers that skip point validation are exposed to invalid-curve "
        "attacks.",
        "Republish a valid key and ensure verifiers validate points."),
    "jwks-alg-mismatch": (
        "Inconsistent key metadata can push verifiers into the wrong algorithm "
        "path (a precondition for algorithm-confusion bugs).",
        "Bind each key to an 'alg' that matches its kty/curve."),
    "jwks-rsa1_5": (
        "RSA1_5 key encryption is vulnerable to Bleichenbacher padding-oracle "
        "attacks.",
        "Use RSA-OAEP-256 or ECDH-ES for encryption keys."),
    "jwks-use-conflict": (
        "Keys valid for both signing and encryption enable cross-protocol "
        "attacks and confuse key selection.",
        "Use separate keys per purpose and keep use/key_ops/alg consistent."),
    "jwks-bad-use": (
        "Verifiers may ignore or misclassify the key.",
        "Set 'use' to 'sig' or 'enc'."),
    "jwks-private-key-ops": (
        "A public key advertising private operations (sign/decrypt) often means "
        "it was exported straight from a private key — private fields may "
        "leak in other environments or versions.",
        "Publish public-key-only JWKs; strip key_ops or set it to verify/encrypt."),
    "jwks-remote-ref": (
        "Remote key references (jku/x5u) in a JWKS are unusual and, if honored, "
        "can let an attacker point verifiers at keys they control.",
        "Remove jku/x5u from published keys; never trust them in token headers."),
    "jwks-x5t-mismatch": (
        "Clients pinning by thumbprint will select the wrong key or fail.",
        "Recompute x5t/x5t#S256 from the published certificate."),
    "jwks-x5c-expired": (
        "Strict verifiers that validate x5c will reject tokens; lax ones are "
        "trusting an expired certificate.",
        "Rotate the certificate/key and remove expired entries."),
    "jwks-x5c-expiring": (
        "Imminent expiry risks an outage for clients that validate x5c.",
        "Rotate the certificate ahead of expiry."),
    "jwks-x5c-not-yet-valid": (
        "Clients that validate x5c will reject this key until the date passes.",
        "Check the issuing clock/process; publish only currently valid certs."),
    "jwks-x5c-weak-sig": (
        "MD5/SHA-1 certificate signatures are collision-prone.",
        "Reissue the certificate with SHA-256 or better."),
    "jwks-x5c-mismatch": (
        "Clients that trust the certificate and clients that trust the JWK "
        "will verify against different keys.",
        "Republish so the x5c leaf certificate carries the JWK's public key."),
    "jwks-x5c-malformed": (
        "Clients that validate x5c will fail to load the key.",
        "Publish a valid, standard-base64 DER certificate chain."),
    "jwks-key-reuse": (
        "One key under several kids complicates rotation and revocation.",
        "Give each key a single kid and retire aliases."),
    "jwks-shared-across-targets": (
        "Different issuers sharing one signing key means a token from one may "
        "be accepted by another — and may indicate a default/sample key shipped "
        "with a product.",
        "Use unique signing keys per issuer/tenant; replace any vendor default "
        "keys."),
    "tls-cert-invalid": (
        "Clients may be exposed to MITM, or will fail to connect, depending on "
        "enforcement.",
        "Install a valid, trusted certificate matching the hostname."),
    "tls-weak-protocol": (
        "Deprecated TLS versions are vulnerable to known downgrade/crypto attacks.",
        "Disable TLS < 1.2; prefer TLS 1.3."),
    "tls-cert-expired": (
        "An expired certificate breaks trust and client connectivity.",
        "Renew/replace the certificate and automate renewal."),
    "tls-cert-expiring": (
        "Imminent expiry risks an outage and rushed, error-prone replacement.",
        "Renew ahead of expiry and automate renewal/monitoring."),
    "probe-tls": (
        "TLS problems on this endpoint expose its traffic to MITM.",
        "Fix the certificate/chain and enforce HTTPS."),
    "probe-cross-redirect": (
        "Cross-host redirects can leak codes/tokens or be abused as an open "
        "redirect in the auth flow.",
        "Restrict redirects to trusted hosts; verify this is intended."),
    "probe-server-banner": (
        "Version disclosure helps an attacker target known CVEs.",
        "Suppress or genericize the Server header."),
    "probe-cors": (
        "A wildcard CORS policy (especially with credentials) can expose token/"
        "userinfo responses to malicious origins.",
        "Restrict Access-Control-Allow-Origin to trusted origins; never combine "
        "'*' with credentials."),
    "probe-userinfo-open": (
        "An unauthenticated userinfo response may leak user claims/PII.",
        "Require a valid access token; return 401 otherwise."),
    "probe-no-hsts": (
        "Without HSTS, clients can be downgraded to HTTP and MITM'd.",
        "Send Strict-Transport-Security with a long max-age."),
    "webfinger-present": (
        "WebFinger can enable account/tenant enumeration, and a reflected/fetched "
        "'resource' param can be an SSRF/open-redirect vector.",
        "Limit WebFinger disclosure; validate the 'resource' parameter."),
    "dynreg-open": (
        "Unauthenticated client registration lets anyone create clients with "
        "arbitrary redirect_uris — a direct path to phishing/token theft.",
        "Require authentication / initial access token and validate redirect_uris. "
        "Remove any client created by this probe."),
}


class Report:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.meta = {}

    def add(self, severity, code, title, detail="", location="", manual=False,
            pointer="", evidence=""):
        impact, recommendation = CATALOG.get(code, ("", ""))
        self.findings.append({
            "severity": severity.upper(),
            "code": code,
            "title": title,
            "detail": detail,
            "location": location or self.meta.get("discovery_url", ""),
            "pointer": pointer,            # JSON path within the source document
            "evidence": evidence,          # the exact offending value
            "impact": impact,              # why it matters
            "recommendation": recommendation,  # how to fix it
            "manual": bool(manual),
        })

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #

class Http:
    def __init__(self, timeout=15, verify=True, proxy=None, headers=None, ua=None):
        self.timeout = timeout
        self.verify = verify
        self.s = requests.Session()
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.s.headers.update(
            {"User-Agent": ua or f"basic_oidc_scanner/{__version__} (+pentest)"})
        if headers:
            self.s.headers.update(headers)

    def request(self, method, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify)
        kw.setdefault("allow_redirects", False)
        return self.s.request(method, url, **kw)


# --------------------------------------------------------------------------- #
# Discovery document retrieval (with RFC 8414 fallbacks)
# --------------------------------------------------------------------------- #

WK_OIDC = ".well-known/openid-configuration"
WK_OAUTH = ".well-known/oauth-authorization-server"


def candidate_discovery_urls(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    if raw.rstrip("/").endswith(("openid-configuration", "oauth-authorization-server")) \
            or "/.well-known/" in raw:
        return [raw]
    p = urlparse(raw)
    base = f"{p.scheme}://{p.netloc}"
    path = p.path.strip("/")
    cands = [base.rstrip("/") + "/" + WK_OIDC if not path
             else f"{base}/{path}/{WK_OIDC}"]
    if path:
        cands.append(f"{base}/{WK_OAUTH}/{path}")
        cands.append(f"{base}/{path}/{WK_OAUTH}")
    else:
        cands.append(f"{base}/{WK_OAUTH}")
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def fetch_json(http, url, rep, what, soft=False):
    try:
        r = http.request("GET", url, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        if not soft:
            rep.add("HIGH", "tls-error", f"TLS verification failed for {what}",
                    detail=str(e), location=url)
        return None, None
    except requests.RequestException as e:
        if not soft:
            rep.add("INFO", "fetch-error", f"Could not fetch {what}",
                    detail=str(e), location=url)
        return None, None
    if r.status_code != 200:
        if not soft:
            rep.add("MEDIUM", "bad-status",
                    f"{what} returned HTTP {r.status_code}", location=url)
        return None, r
    try:
        return r.json(), r
    except ValueError:
        if not soft:
            rep.add("MEDIUM", "bad-json", f"{what} is not valid JSON", location=url)
        return None, r


def fetch_discovery(http, target, rep):
    cands = candidate_discovery_urls(target)
    for i, url in enumerate(cands):
        last = (i == len(cands) - 1)
        cfg, _ = fetch_json(http, url, rep, "discovery document", soft=not last)
        if cfg is not None:
            if i > 0:
                rep.add("INFO", "discovery-fallback",
                        "Discovery document found via a fallback location "
                        "(RFC 8414 oauth-authorization-server).", location=url)
            return cfg, url
    return None, cands[-1]


# --------------------------------------------------------------------------- #
# TLS / certificate inspection (issuer host)
# --------------------------------------------------------------------------- #

WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls(host, port, rep, timeout, verify=True):
    if verify:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    _tls_details(ss, rep, host)
                    return
        except ssl.SSLCertVerificationError as e:
            rep.add("HIGH", "tls-cert-invalid",
                    f"TLS certificate failed verification for {host}",
                    location=host, pointer="TLS certificate", evidence=str(e))
        except (ssl.SSLError, OSError) as e:
            rep.add("INFO", "tls-connect-error",
                    f"TLS inspection could not connect to {host}",
                    detail=str(e), location=host)
            return
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                _tls_details(ss, rep, host, verified=False)
    except (ssl.SSLError, OSError) as e:
        rep.add("INFO", "tls-connect-error",
                f"TLS inspection could not connect to {host}",
                detail=str(e), location=host)


def _tls_details(ss, rep, host, verified=True):
    proto = ss.version()
    rep.meta.setdefault("tls", {})[host] = {"protocol": proto}
    if proto in WEAK_TLS:
        rep.add("HIGH", "tls-weak-protocol",
                f"{host} negotiated a weak TLS protocol.",
                location=host, pointer="TLS protocol", evidence=proto)
    else:
        rep.add("INFO", "tls-protocol", f"{host} TLS protocol: {proto}.",
                location=host)
    not_after = None
    if verified:
        not_after = (ss.getpeercert() or {}).get("notAfter")
    else:
        # getpeercert() is empty on unverified handshakes; parse the raw cert.
        not_after = _not_after_from_der(ss.getpeercert(binary_form=True))
        if not_after is None:
            rep.add("INFO", "tls-cert-not-inspected",
                    f"{host} certificate expiry not inspected (unverified "
                    "handshake; install 'cryptography' to enable).", location=host)
    if not_after:
        try:
            exp = ssl.cert_time_to_seconds(not_after)
        except ValueError:
            return
        days = (exp - time.time()) / 86400
        rep.meta["tls"][host]["days_to_expiry"] = round(days, 1)
        if days < 0:
            rep.add("HIGH", "tls-cert-expired",
                    f"{host} certificate has expired.",
                    location=host, pointer="TLS certificate notAfter",
                    evidence=not_after)
        elif days < 15:
            rep.add("MEDIUM", "tls-cert-expiring",
                    f"{host} certificate expires in {days:.0f} days.",
                    location=host, pointer="TLS certificate notAfter",
                    evidence=not_after)


def _not_after_from_der(der):
    """Return notAfter in OpenSSL text format ('Jun  1 12:00:00 2027 GMT')."""
    if not der:
        return None
    if HAVE_CRYPTO:
        try:
            cert = x509.load_der_x509_certificate(der)
            na = getattr(cert, "not_valid_after_utc", None) or \
                cert.not_valid_after.replace(tzinfo=timezone.utc)
            return na.strftime("%b %d %H:%M:%S %Y GMT")
        except Exception:
            return None
    # stdlib fallback: CPython's private cert decoder (needs a file on disk)
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return None
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        return decode(path).get("notAfter")
    except Exception:
        return None
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Discovery document checks
# --------------------------------------------------------------------------- #

ENDPOINT_KEYS = [
    "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
    "registration_endpoint", "end_session_endpoint", "introspection_endpoint",
    "revocation_endpoint", "device_authorization_endpoint",
    "pushed_authorization_request_endpoint", "backchannel_authentication_endpoint",
]

GRANT_CODE = {
    "implicit": "grant-implicit",
    "password": "grant-password",
    "urn:ietf:params:oauth:grant-type:token-exchange": "grant-token-exchange",
}
GRANT_TITLE = {
    "implicit": "Implicit grant ('implicit') supported.",
    "password": "Resource Owner Password Credentials grant ('password') supported.",
    "urn:ietf:params:oauth:grant-type:token-exchange":
        "Token exchange grant supported.",
}
GRANT_SEV = {"implicit": "HIGH", "password": "HIGH",
             "urn:ietf:params:oauth:grant-type:token-exchange": "LOW"}


def check_issuer(cfg, discovery_url, rep):
    issuer = cfg.get("issuer")
    rep.meta["issuer"] = issuer
    if not issuer:
        rep.add("HIGH", "issuer-missing", "No 'issuer' claim in discovery document.",
                pointer="issuer")
        return
    if not issuer.startswith("https://"):
        rep.add("HIGH", "issuer-not-https", "Issuer is not HTTPS.",
                pointer="issuer", evidence=issuer)
    # Valid locations for this issuer: OIDC (path appended) and RFC 8414
    # (well-known inserted between host and path, or appended).
    ip = urlparse(issuer.rstrip("/"))
    origin, ipath = f"{ip.scheme}://{ip.netloc}", ip.path.strip("/")
    expected = {f"{issuer.rstrip('/')}/{WK_OIDC}", f"{issuer.rstrip('/')}/{WK_OAUTH}"}
    expected.add(f"{origin}/{WK_OAUTH}" + (f"/{ipath}" if ipath else ""))
    served = discovery_url.rstrip("/")
    if served not in expected and served.replace(":443", "", 1) not in expected:
        rep.add("LOW", "issuer-url-mismatch",
                "Issuer does not match the discovery URL.", pointer="issuer",
                evidence=f"issuer={issuer!r} but served from {discovery_url!r}",
                manual=True)
    if "?" in issuer or "#" in issuer:
        rep.add("MEDIUM", "issuer-has-query",
                "Issuer contains a query/fragment component.",
                pointer="issuer", evidence=issuer)


def check_https_endpoints(cfg, rep):
    issuer_host = urlparse(cfg.get("issuer", "")).hostname
    for key in ENDPOINT_KEYS:
        val = cfg.get(key)
        if not val:
            continue
        p = urlparse(val)
        if p.scheme != "https":
            rep.add("HIGH", "endpoint-not-https", f"{key} is not HTTPS.",
                    location=val, pointer=key, evidence=val)
        if issuer_host and p.hostname and p.hostname != issuer_host:
            rep.add("LOW", "endpoint-off-issuer-host",
                    f"{key} is on a different host than the issuer.",
                    location=val, pointer=key,
                    evidence=f"{p.hostname} ≠ issuer host {issuer_host}",
                    manual=True)


def check_algorithms(cfg, rep):
    for k in [k for k in cfg if k.endswith("_signing_alg_values_supported")]:
        algs = cfg.get(k) or []
        low = [a.lower() for a in algs]
        if "none" in low:
            sev = "CRITICAL" if "id_token" in k else "HIGH"
            rep.add(sev, "alg-none", f"'{k}' advertises 'none'.",
                    pointer=f"{k}[{low.index('none')}]", evidence=f"{k} = {algs}")
        hs = [a for a in algs if a.upper().startswith("HS")]
        asym = [a for a in algs if a.upper().startswith(("RS", "ES", "PS"))]
        if hs and asym:
            rep.add("MEDIUM", "alg-confusion-surface",
                    f"'{k}' allows both symmetric (HS*) and asymmetric algorithms.",
                    pointer=k, evidence=f"symmetric={hs}  asymmetric={asym}",
                    manual=True)


def check_pkce(cfg, rep):
    methods = cfg.get("code_challenge_methods_supported")
    grants = cfg.get("grant_types_supported") or ["authorization_code"]
    uses_code = any("authorization_code" in g or g == "code" for g in grants) or \
        any("code" in rt for rt in (cfg.get("response_types_supported") or []))
    if methods is None:
        if uses_code:
            rep.add("MEDIUM", "pkce-not-advertised",
                    "PKCE is not advertised for an authorization-code-capable "
                    "server.", pointer="code_challenge_methods_supported",
                    evidence="key absent", manual=True)
        return
    low = [m.lower() for m in methods]
    if "plain" in low:
        rep.add("MEDIUM", "pkce-plain", "PKCE 'plain' method supported.",
                pointer=f"code_challenge_methods_supported[{low.index('plain')}]",
                evidence=f"code_challenge_methods_supported = {methods}")
    if "s256" not in low:
        rep.add("MEDIUM", "pkce-no-s256", "PKCE advertised without 'S256'.",
                pointer="code_challenge_methods_supported",
                evidence=f"code_challenge_methods_supported = {methods}")


def check_grants_and_responses(cfg, rep):
    grants = cfg.get("grant_types_supported") or []
    for g in grants:
        if g in GRANT_CODE:
            rep.add(GRANT_SEV[g], GRANT_CODE[g], GRANT_TITLE[g],
                    pointer=f"grant_types_supported[{grants.index(g)}]", evidence=g)
    rtypes = cfg.get("response_types_supported") or []
    for rt in rtypes:
        norm = rt.strip()
        ptr = f"response_types_supported[{rtypes.index(rt)}]"
        toks = norm.split()
        if "token" in toks and "code" not in toks:
            title = (f"Implicit response type ('{norm}') supported."
                     if norm in ("token", "id_token token")
                     else "Response type returns a token directly (implicit-style).")
            rep.add("HIGH", "implicit-response-type", title,
                    pointer=ptr, evidence=rt)


def check_auth_methods(cfg, rep):
    for k in [k for k in cfg if k.endswith("_endpoint_auth_methods_supported")]:
        methods = cfg.get(k) or []
        low = [m.lower() for m in methods]
        if "none" in low:
            rep.add("MEDIUM", "auth-method-none",
                    f"'{k}' allows 'none' (public/unauthenticated client).",
                    pointer=f"{k}[{low.index('none')}]",
                    evidence=f"{k} = {methods}", manual=True)


def check_request_object(cfg, rep):
    if cfg.get("request_uri_parameter_supported"):
        reg = cfg.get("require_request_uri_registration")
        if reg is False or reg is None:
            rep.add("MEDIUM", "request-uri-ssrf",
                    "request_uri parameter supported without required registration.",
                    pointer="require_request_uri_registration",
                    evidence=f"request_uri_parameter_supported=true, "
                             f"require_request_uri_registration={reg}", manual=True)
    if cfg.get("request_parameter_supported"):
        rep.add("INFO", "request-param",
                "request parameter (JWT request objects) supported.",
                pointer="request_parameter_supported", evidence="true", manual=True)


def check_misc(cfg, rep):
    if cfg.get("registration_endpoint"):
        rep.add("LOW", "dynamic-registration",
                "Dynamic Client Registration endpoint advertised.",
                location=cfg["registration_endpoint"],
                pointer="registration_endpoint",
                evidence=cfg["registration_endpoint"], manual=True)
    if "openid" not in (cfg.get("scopes_supported") or ["openid"]):
        rep.add("INFO", "scopes-no-openid",
                "scopes_supported does not list 'openid'.",
                pointer="scopes_supported", evidence=f"{cfg.get('scopes_supported')}")
    modes = cfg.get("response_modes_supported") or []
    for rm in modes:
        if rm == "form_post":
            rep.add("INFO", "form-post", "form_post response mode supported.",
                    pointer=f"response_modes_supported[{modes.index(rm)}]",
                    evidence=rm)
    if not cfg.get("end_session_endpoint") and \
            not cfg.get("backchannel_logout_supported"):
        rep.add("INFO", "no-logout", "No RP-/back-channel logout advertised.")


# --------------------------------------------------------------------------- #
# JWKS analysis
# --------------------------------------------------------------------------- #

def b64url_decode(val):
    pad = "=" * (-len(val) % 4)
    return base64.urlsafe_b64decode(val + pad)


def b64url_int(val):
    try:
        raw = b64url_decode(val)
    except Exception:
        return None
    return int.from_bytes(raw, "big") if raw else None


def b64url_len_bits(val):
    n = b64url_int(val)
    return n.bit_length() if n else None


PRIVATE_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "k"}
PRIVATE_OPS = {"sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"}
SIG_OPS, ENC_OPS = {"sign", "verify"}, {"encrypt", "decrypt", "wrapKey", "unwrapKey"}

# alg -> key types it can legitimately be used with (RFC 7518 / 8037 / 8812)
ALG_KTY = [
    (re.compile(r"^(RS|PS)\d+$|^RSA1_5$|^RSA-OAEP"), {"RSA"}),
    (re.compile(r"^ES\d+K?$"), {"EC"}),
    (re.compile(r"^ECDH-ES"), {"EC", "OKP"}),
    (re.compile(r"^(EdDSA|Ed25519|Ed448)$"), {"OKP"}),
    (re.compile(r"^HS\d+$|^A\d+(GCM)?KW$|^dir$|^PBES2"), {"oct"}),
]
ENC_ALG = re.compile(r"^(RSA1_5|RSA-OAEP|ECDH-ES|A\d+(GCM)?KW|dir|PBES2)")
ALG_CRV = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521",
           "ES256K": "secp256k1"}

# Short Weierstrass curves y^2 = x^3 + ax + b (mod p): (p, a, b, coord bytes)
EC_CURVES = {
    "P-256": (2**256 - 2**224 + 2**192 + 2**96 - 1, -3,
              0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
              32),
    "P-384": (2**384 - 2**128 - 2**96 + 2**32 - 1, -3,
              int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
                  "c656398d8a2ed19d2a85c8edd3ec2aef", 16),
              48),
    "P-521": (2**521 - 1, -3,
              int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
                  "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50"
                  "3f00", 16),
              66),
    "secp256k1": (2**256 - 2**32 - 977, 0, 7, 32),
}
OKP_CURVES = {"Ed25519": 32, "Ed448": 57, "X25519": 32, "X448": 56}


def _primes_below(limit):
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i, v in enumerate(sieve) if v]


SMALL_PRIMES = _primes_below(20000)

# ROCA (CVE-2017-15361, Infineon RSALib) fingerprint: affected moduli satisfy
# n mod p ∈ <65537> (mod p) for every one of these small primes.
ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
               67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
               137, 139, 149, 151, 157, 163, 167]


def _roca_subgroups():
    out = {}
    for p in ROCA_PRIMES:
        s, x = set(), 1
        while x not in s:
            s.add(x)
            x = x * 65537 % p
        out[p] = s
    return out


ROCA_SUBGROUPS = _roca_subgroups()


def roca_fingerprint(n):
    return all(n % p in ROCA_SUBGROUPS[p] for p in ROCA_PRIMES)


def fermat_factor(n, rounds=20000):
    """Factor n quickly if its primes are unusually close together."""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def small_factor(n):
    for p in SMALL_PRIMES:
        if n % p == 0 and n != p:
            return p
    return None


def jwk_thumbprint(k):
    """RFC 7638 SHA-256 thumbprint (base64url), or None if not computable."""
    req = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"),
           "OKP": ("crv", "kty", "x"), "oct": ("k", "kty")}.get(k.get("kty"))
    if not req or any(not isinstance(k.get(f), str) for f in req):
        return None
    canon = json.dumps({f: k[f] for f in req}, separators=(",", ":"),
                       sort_keys=True)
    digest = hashlib.sha256(canon.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _snippet(val, n=40):
    """Short, safe preview of a sensitive value (never dump the whole secret)."""
    s = str(val)
    return s[:n] + ("…" if len(s) > n else "")


def _check_rsa(k, i, kid, rep, location):
    n, e = b64url_int(k.get("n", "")), b64url_int(k.get("e", ""))
    if not n or not e:
        rep.add("MEDIUM", "jwks-malformed-key",
                f"Key '{kid}' is RSA but 'n'/'e' are missing or undecodable.",
                location=location, pointer=f"keys[{i}]", evidence=f"kid={kid!r}")
        return
    bits = n.bit_length()
    if bits < 2048:
        rep.add("HIGH", "jwks-weak-rsa",
                f"Key '{kid}' RSA modulus is {bits} bits (< 2048).",
                location=location, pointer=f"keys[{i}].n",
                evidence=f"kid={kid!r} modulus={bits} bits")
    else:
        rep.add("INFO", "jwks-rsa-ok", f"Key '{kid}' RSA {bits} bits, e={e}.",
                location=location, pointer=f"keys[{i}]")
    # exponent sanity
    if e == 1:
        rep.add("CRITICAL", "jwks-rsa-e1",
                f"Key '{kid}' has public exponent e=1.", location=location,
                pointer=f"keys[{i}].e", evidence=f"kid={kid!r} e=1")
    elif e % 2 == 0:
        rep.add("HIGH", "jwks-rsa-bad-e",
                f"Key '{kid}' has an even public exponent (not a valid RSA key).",
                location=location, pointer=f"keys[{i}].e",
                evidence=f"kid={kid!r} e={e}")
    elif e < 65537:
        rep.add("LOW", "jwks-rsa-small-e",
                f"Key '{kid}' uses a small public exponent (e={e}).",
                location=location, pointer=f"keys[{i}].e",
                evidence=f"kid={kid!r} e={e}")
    # factorability: small primes, then Fermat (close primes)
    f = small_factor(n)
    how = "trial division"
    if not f:
        pq = fermat_factor(n)
        if pq:
            f, how = pq[0], "Fermat (p and q too close)"
    if f:
        rep.add("CRITICAL", "jwks-rsa-factored",
                f"Key '{kid}' RSA modulus was factored ({how}).",
                location=location, pointer=f"keys[{i}].n",
                evidence=f"kid={kid!r} factor={_snippet(f, 24)} ({f.bit_length()} bits)")
    elif bits >= 512 and roca_fingerprint(n):
        rep.add("HIGH", "jwks-rsa-roca",
                f"Key '{kid}' matches the ROCA (CVE-2017-15361) fingerprint.",
                location=location, pointer=f"keys[{i}].n",
                evidence=f"kid={kid!r} modulus={bits} bits", manual=True)


def _check_ec(k, i, kid, rep, location):
    crv = k.get("crv", "")
    x, y = k.get("x"), k.get("y")
    if crv not in EC_CURVES:
        rep.add("MEDIUM", "jwks-ec-curve",
                f"Key '{kid}' uses a non-standard/unsupported curve '{crv}'.",
                location=location, pointer=f"keys[{i}].crv",
                evidence=f"kid={kid!r} crv={crv!r}")
        return
    rep.add("INFO", "jwks-ec", f"Key '{kid}' EC curve {crv}.",
            location=location, pointer=f"keys[{i}].crv")
    p, a, b, size = EC_CURVES[crv]
    try:
        xb, yb = b64url_decode(x or ""), b64url_decode(y or "")
    except Exception:
        xb = yb = b""
    if not xb or not yb:
        rep.add("MEDIUM", "jwks-malformed-key",
                f"Key '{kid}' is EC but 'x'/'y' are missing or undecodable.",
                location=location, pointer=f"keys[{i}]", evidence=f"kid={kid!r}")
        return
    if len(xb) != size or len(yb) != size:
        rep.add("LOW", "jwks-ec-coord-length",
                f"Key '{kid}' coordinates are not {size} bytes as {crv} requires.",
                location=location, pointer=f"keys[{i}].x/y",
                evidence=f"len(x)={len(xb)} len(y)={len(yb)}")
    X, Y = int.from_bytes(xb, "big"), int.from_bytes(yb, "big")
    if X >= p or Y >= p or (Y * Y - (X ** 3 + a * X + b)) % p != 0:
        rep.add("HIGH", "jwks-ec-off-curve",
                f"Key '{kid}' public point is not on {crv}.",
                location=location, pointer=f"keys[{i}].x/y",
                evidence=f"kid={kid!r} x={_snippet(x, 20)} y={_snippet(y, 20)}")


def _check_okp(k, i, kid, rep, location):
    crv = k.get("crv", "")
    if crv not in OKP_CURVES:
        rep.add("MEDIUM", "jwks-ec-curve",
                f"Key '{kid}' uses an unknown OKP curve '{crv}'.",
                location=location, pointer=f"keys[{i}].crv",
                evidence=f"kid={kid!r} crv={crv!r}")
        return
    rep.add("INFO", "jwks-okp", f"Key '{kid}' OKP curve {crv}.",
            location=location, pointer=f"keys[{i}].crv")
    try:
        xl = len(b64url_decode(k.get("x", "")))
    except Exception:
        xl = 0
    if xl != OKP_CURVES[crv]:
        rep.add("LOW", "jwks-ec-coord-length",
                f"Key '{kid}' 'x' is {xl} bytes; {crv} requires {OKP_CURVES[crv]}.",
                location=location, pointer=f"keys[{i}].x", evidence=f"len(x)={xl}")


def _check_alg_use(k, i, kid, rep, location):
    kty, alg = k.get("kty", ""), str(k.get("alg", ""))
    use, ops = k.get("use"), k.get("key_ops")
    if alg and alg.lower() != "none":
        allowed = next((ks for rx, ks in ALG_KTY if rx.search(alg)), None)
        if allowed is not None and kty not in allowed:
            rep.add("MEDIUM", "jwks-alg-mismatch",
                    f"Key '{kid}' declares alg '{alg}' but kty is '{kty}'.",
                    location=location, pointer=f"keys[{i}].alg",
                    evidence=f"kid={kid!r} kty={kty} alg={alg}")
        if alg in ALG_CRV and k.get("crv") and k.get("crv") != ALG_CRV[alg]:
            rep.add("MEDIUM", "jwks-alg-mismatch",
                    f"Key '{kid}' declares alg '{alg}' but curve is "
                    f"'{k.get('crv')}' (expected {ALG_CRV[alg]}).",
                    location=location, pointer=f"keys[{i}].crv",
                    evidence=f"kid={kid!r} alg={alg} crv={k.get('crv')}")
        if alg == "RSA1_5":
            rep.add("LOW", "jwks-rsa1_5",
                    f"Key '{kid}' is bound to RSA1_5 key encryption.",
                    location=location, pointer=f"keys[{i}].alg",
                    evidence=f"kid={kid!r} alg=RSA1_5")
        if use == "sig" and ENC_ALG.search(alg) or \
                use == "enc" and not ENC_ALG.search(alg) and allowed is not None:
            rep.add("LOW", "jwks-use-conflict",
                    f"Key '{kid}' has use='{use}' but an alg for the other "
                    f"purpose ('{alg}').", location=location,
                    pointer=f"keys[{i}].use", evidence=f"use={use} alg={alg}")
    if use is not None and use not in ("sig", "enc"):
        rep.add("LOW", "jwks-bad-use",
                f"Key '{kid}' has an unrecognised 'use' value.",
                location=location, pointer=f"keys[{i}].use", evidence=f"use={use!r}")
    if isinstance(ops, list):
        priv = sorted(PRIVATE_OPS.intersection(ops))
        if priv:
            rep.add("LOW", "jwks-private-key-ops",
                    f"Published key '{kid}' advertises private-key operations.",
                    location=location, pointer=f"keys[{i}].key_ops",
                    evidence=f"kid={kid!r} key_ops={ops}", manual=True)
        if (use == "sig" and ENC_OPS.intersection(ops)) or \
                (use == "enc" and SIG_OPS.intersection(ops)):
            rep.add("LOW", "jwks-use-conflict",
                    f"Key '{kid}' has use='{use}' but conflicting key_ops.",
                    location=location, pointer=f"keys[{i}].key_ops",
                    evidence=f"use={use} key_ops={ops}")
    for ref in ("jku", "x5u"):
        if k.get(ref):
            rep.add("LOW", "jwks-remote-ref",
                    f"Key '{kid}' references remote key material via '{ref}'.",
                    location=location, pointer=f"keys[{i}].{ref}",
                    evidence=f"{ref}={k[ref]}", manual=True)


def _check_x5c(k, i, kid, rep, location):
    chain = k.get("x5c")
    if not chain:
        return
    if not isinstance(chain, list) or not isinstance(chain[0], str):
        rep.add("LOW", "jwks-x5c-malformed", f"Key '{kid}' has a malformed x5c.",
                location=location, pointer=f"keys[{i}].x5c")
        return
    try:
        der = base64.b64decode(chain[0])  # x5c is standard base64, not base64url
    except Exception:
        rep.add("LOW", "jwks-x5c-malformed",
                f"Key '{kid}' x5c[0] is not valid base64.",
                location=location, pointer=f"keys[{i}].x5c[0]")
        return
    # Thumbprints are stdlib-checkable.
    for field, h in (("x5t", hashlib.sha1), ("x5t#S256", hashlib.sha256)):
        if k.get(field):
            want = base64.urlsafe_b64encode(h(der).digest()).rstrip(b"=").decode()
            if k[field].rstrip("=") != want:
                rep.add("MEDIUM", "jwks-x5t-mismatch",
                        f"Key '{kid}' {field} does not match its x5c certificate.",
                        location=location, pointer=f"keys[{i}].{field}",
                        evidence=f"{field}={k[field]} computed={want}")
    if not HAVE_CRYPTO:
        rep.add("INFO", "jwks-x5c-unparsed",
                f"Key '{kid}' has an x5c chain; install 'cryptography' to "
                "inspect it.", location=location, pointer=f"keys[{i}].x5c")
        return
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        rep.add("LOW", "jwks-x5c-malformed",
                f"Key '{kid}' x5c[0] is not a parseable certificate.",
                location=location, pointer=f"keys[{i}].x5c[0]", evidence=str(e))
        return
    subj = cert.subject.rfc4514_string()
    iss = cert.issuer.rfc4514_string()
    rep.add("INFO", "jwks-x5c-subject",
            f"Key '{kid}' certificate subject: {subj}"
            + (" (self-signed)" if subj == iss else f" | issuer: {iss}"),
            location=location, pointer=f"keys[{i}].x5c[0]")
    nb = getattr(cert, "not_valid_before_utc", None) or \
        cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days = (na - now).total_seconds() / 86400
    if days < 0:
        rep.add("MEDIUM", "jwks-x5c-expired",
                f"Key '{kid}' certificate expired {-days:.0f} days ago.",
                location=location, pointer=f"keys[{i}].x5c[0] notAfter",
                evidence=na.isoformat())
    elif days < 30:
        rep.add("LOW", "jwks-x5c-expiring",
                f"Key '{kid}' certificate expires in {days:.0f} days.",
                location=location, pointer=f"keys[{i}].x5c[0] notAfter",
                evidence=na.isoformat())
    if nb > now:
        rep.add("LOW", "jwks-x5c-not-yet-valid",
                f"Key '{kid}' certificate is not valid until {nb.date()}.",
                location=location, pointer=f"keys[{i}].x5c[0] notBefore",
                evidence=nb.isoformat())
    algo = getattr(cert.signature_hash_algorithm, "name", "")
    if algo in ("md5", "sha1"):
        rep.add("LOW", "jwks-x5c-weak-sig",
                f"Key '{kid}' certificate is signed with {algo.upper()}.",
                location=location, pointer=f"keys[{i}].x5c[0]",
                evidence=f"signature hash={algo}")
    # Does the certificate actually carry the same public key as the JWK?
    pub = cert.public_key()
    match = None
    if k.get("kty") == "RSA" and isinstance(pub, _crypto_rsa.RSAPublicKey):
        nums = pub.public_numbers()
        match = (nums.n == b64url_int(k.get("n", "")) and
                 nums.e == b64url_int(k.get("e", "")))
    elif k.get("kty") == "EC" and isinstance(pub, _crypto_ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        match = (nums.x == b64url_int(k.get("x", "")) and
                 nums.y == b64url_int(k.get("y", "")))
    elif k.get("kty") in ("RSA", "EC"):
        match = False
    if match is False:
        rep.add("HIGH", "jwks-x5c-mismatch",
                f"Key '{kid}' x5c certificate carries a different public key "
                "than the JWK.", location=location, pointer=f"keys[{i}].x5c[0]",
                evidence=f"kid={kid!r} cert subject={subj}")


def check_jwks(jwks, rep, location, cfg=None):
    keys = (jwks or {}).get("keys")
    if not isinstance(keys, list):
        rep.add("MEDIUM", "jwks-malformed", "JWKS has no 'keys' array.",
                location=location, pointer="keys")
        return
    rep.meta["jwks_key_count"] = len(keys)
    rep.meta["jwks_thumbprints"] = []
    if not keys:
        rep.add("LOW", "jwks-empty", "JWKS contains no keys.",
                location=location, pointer="keys")
    kids, thumbs = [], {}
    for i, k in enumerate(keys):
        if not isinstance(k, dict):
            rep.add("MEDIUM", "jwks-malformed-key", f"keys[{i}] is not an object.",
                    location=location, pointer=f"keys[{i}]")
            continue
        kid = k.get("kid", f"<no kid #{i}>")
        kids.append(k.get("kid"))
        kty = k.get("kty", "")
        tp = jwk_thumbprint(k)
        if tp:
            thumbs.setdefault(tp, []).append(kid)
            rep.meta["jwks_thumbprints"].append(
                {"kid": k.get("kid"), "kty": kty, "thumbprint": tp})
        exposed = sorted(PRIVATE_FIELDS.intersection(k.keys()))
        if kty == "oct":
            exposed = [f for f in exposed if f != "k"]  # reported separately
        if exposed:
            ev = "  ".join(f"{f}={_snippet(k[f])}" for f in exposed)
            rep.add("CRITICAL", "jwks-private-key",
                    f"Key '{kid}' exposes private/secret material "
                    f"({', '.join(exposed)}) in the public JWKS.",
                    location=location,
                    pointer=f"keys[{i}].{exposed[0]}"
                            + (f" (+{len(exposed)-1} more)" if len(exposed) > 1 else ""),
                    evidence=f"kid={kid!r} kty={kty}  {ev}")
        if kty == "oct":
            rep.add("CRITICAL", "jwks-symmetric",
                    f"Key '{kid}' is a published symmetric (oct) key.",
                    location=location, pointer=f"keys[{i}].k",
                    evidence=f"kid={kid!r} k={_snippet(k.get('k',''))}")
        elif kty == "RSA":
            _check_rsa(k, i, kid, rep, location)
        elif kty == "EC":
            _check_ec(k, i, kid, rep, location)
        elif kty == "OKP":
            _check_okp(k, i, kid, rep, location)
        else:
            rep.add("MEDIUM", "jwks-malformed-key",
                    f"Key '{kid}' has a missing or unknown kty.",
                    location=location, pointer=f"keys[{i}].kty",
                    evidence=f"kty={kty!r}")
        _check_alg_use(k, i, kid, rep, location)
        _check_x5c(k, i, kid, rep, location)
        if "kid" not in k and len(keys) > 1:
            rep.add("LOW", "jwks-no-kid",
                    f"Key #{i} has no 'kid' while multiple keys exist.",
                    location=location, pointer=f"keys[{i}].kid", evidence="kid absent")
        if str(k.get("alg", "")).lower() == "none":
            rep.add("HIGH", "jwks-key-alg-none",
                    f"Key '{kid}' declares alg 'none'.",
                    location=location, pointer=f"keys[{i}].alg", evidence="none")
    present = [x for x in kids if x]
    dupes = {x for x in present if present.count(x) > 1}
    if dupes:
        rep.add("MEDIUM", "jwks-dup-kid",
                f"Duplicate 'kid' values in JWKS: {sorted(dupes)}",
                location=location, pointer="keys[*].kid",
                evidence=f"duplicates={sorted(dupes)}")
    for tp, owners in thumbs.items():
        if len(owners) > 1 and len(set(map(str, owners))) > 1:
            rep.add("MEDIUM", "jwks-key-reuse",
                    "The same key material is published under multiple kids.",
                    location=location, pointer="keys[*]",
                    evidence=f"kids={owners} thumbprint={tp}")
    # Advertised signing algorithms that no published key can verify.
    if cfg and keys:
        have = {k.get("kty") for k in keys if isinstance(k, dict)
                and k.get("use", "sig") == "sig"}
        algs = cfg.get("id_token_signing_alg_values_supported") or []
        need = {a: next((ks for rx, ks in ALG_KTY if rx.search(a)), None)
                for a in algs if a.lower() != "none"}
        orphans = [a for a, ks in need.items()
                   if ks and "oct" not in ks and not (ks & have)]
        if orphans:
            rep.add("INFO", "jwks-alg-no-key",
                    "Advertised id_token signing algorithms have no matching "
                    "key type in the JWKS.",
                    pointer="id_token_signing_alg_values_supported",
                    evidence=f"{orphans} (JWKS key types: {sorted(have)})")


def flag_cross_target_keys(reports):
    """Flag identical keys published by different targets (bulk scans)."""
    seen = {}
    for r in reports:
        for t in r.meta.get("jwks_thumbprints", []):
            seen.setdefault(t["thumbprint"], set()).add(r.meta.get("issuer")
                                                        or r.target)
    for r in reports:
        me = r.meta.get("issuer") or r.target
        for t in r.meta.get("jwks_thumbprints", []):
            others = sorted(seen[t["thumbprint"]] - {me})
            if others:
                r.add("MEDIUM", "jwks-shared-across-targets",
                      f"Key '{t['kid']}' is also published by "
                      f"{len(others)} other scanned target(s).",
                      pointer="jwks", evidence=f"thumbprint={t['thumbprint']} "
                      f"also at: {', '.join(others[:5])}", manual=True)


# --------------------------------------------------------------------------- #
# Active endpoint probing (opt-in)
# --------------------------------------------------------------------------- #

def probe_endpoint(http, key, url, rep):
    result = {"endpoint": key, "url": url}
    try:
        r = http.request("GET", url)
    except requests.exceptions.SSLError as e:
        rep.add("HIGH", "probe-tls", f"{key}: TLS verification failed.",
                location=url, pointer=f"{key} (GET)", evidence=str(e))
        result["error"] = "tls"
        rep.meta.setdefault("probes", []).append(result)
        return
    except requests.RequestException as e:
        result["error"] = str(e)
        rep.meta.setdefault("probes", []).append(result)
        return

    result["status"] = r.status_code
    result["server"] = r.headers.get("Server", "")

    if r.is_redirect or 300 <= r.status_code < 400:
        loc = r.headers.get("Location", "")
        result["redirect"] = loc
        src_host = urlparse(url).hostname
        dst_host = urlparse(urljoin(url, loc)).hostname
        if dst_host and dst_host != src_host:
            rep.add("MEDIUM", "probe-cross-redirect",
                    f"{key} redirects to a different host.",
                    location=url, pointer="response Location header",
                    evidence=f"HTTP {r.status_code}  Location: {loc}", manual=True)

    if result["server"] and re.search(r"\d", result["server"]):
        rep.add("LOW", "probe-server-banner",
                f"{key}: Server header discloses software/version.",
                location=url, pointer="response Server header",
                evidence=f"Server: {result['server']}")

    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        sev = "HIGH" if str(acac).lower() == "true" else "LOW"
        rep.add(sev, "probe-cors",
                f"{key}: Access-Control-Allow-Origin: * "
                + ("with credentials allowed." if sev == "HIGH" else "."),
                location=url, pointer="CORS response headers",
                evidence=f"Access-Control-Allow-Origin: {acao}  "
                         f"Access-Control-Allow-Credentials: {acac}", manual=True)

    if key == "userinfo_endpoint" and r.status_code == 200 and r.text.strip():
        # Many IdPs answer 200 with an error body; only flag real claims.
        try:
            body = r.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and body.get("sub"):
            claims = sorted(k for k in body if k != "sub")
            rep.add("MEDIUM", "probe-userinfo-open",
                    "userinfo endpoint returned user claims to an "
                    "unauthenticated request.",
                    location=url, pointer="unauthenticated GET",
                    evidence=f"HTTP 200, 'sub' present, other claims: "
                             f"{claims[:10]}", manual=True)
        else:
            rep.add("INFO", "probe-userinfo-200",
                    "userinfo endpoint returned HTTP 200 without user claims.",
                    location=url, evidence=f"HTTP 200, {len(r.text)} bytes")

    if urlparse(url).scheme == "https" and \
            "strict-transport-security" not in {h.lower() for h in r.headers}:
        rep.add("LOW", "probe-no-hsts",
                f"{key}: no Strict-Transport-Security header.",
                location=url, pointer="response headers",
                evidence="Strict-Transport-Security absent")

    rep.meta.setdefault("probes", []).append(result)


def probe_webfinger(http, issuer, rep):
    p = urlparse(issuer)
    host = f"{p.scheme}://{p.netloc}"
    wf = f"{host}/.well-known/webfinger"
    resource = f"acct:test@{p.hostname}"
    url = (f"{wf}?resource={quote(resource)}"
           f"&rel=http://openid.net/specs/connect/1.0/issuer")
    try:
        r = http.request("GET", url, allow_redirects=False)
    except requests.RequestException as e:
        rep.add("INFO", "webfinger-none", "No reachable WebFinger endpoint.",
                detail=str(e), location=wf)
        return
    if r.status_code == 200:
        rep.add("LOW", "webfinger-present", "WebFinger endpoint responds.",
                location=wf, pointer="GET ?resource=...",
                evidence=f"HTTP 200, {len(r.text)} bytes", manual=True)
    else:
        rep.add("INFO", "webfinger-status",
                f"WebFinger endpoint returned HTTP {r.status_code}.",
                location=wf, evidence=f"HTTP {r.status_code}")


def probe_dynamic_registration(http, url, rep):
    body = {"redirect_uris": ["https://example.org/cb"],
            "client_name": "basic_oidc_scanner-probe"}
    try:
        r = http.request("POST", url, json=body)
    except requests.RequestException as e:
        rep.add("INFO", "dynreg-error", "Dynamic registration probe failed.",
                detail=str(e), location=url)
        return
    if r.status_code in (200, 201):
        rep.add("HIGH", "dynreg-open",
                f"Unauthenticated Dynamic Client Registration appears to succeed "
                f"(HTTP {r.status_code}).",
                location=url, pointer="unauthenticated POST",
                evidence=f"HTTP {r.status_code}", manual=True)
    elif r.status_code in (401, 403):
        rep.add("INFO", "dynreg-protected",
                f"Dynamic registration requires authentication "
                f"(HTTP {r.status_code}).", location=url)
    else:
        rep.add("INFO", "dynreg-other",
                f"Dynamic registration returned HTTP {r.status_code}.", location=url)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def audit(target, http, probe=False, dynreg=False, fetch_jwks=True, tls_check=True):
    rep = Report(target)
    cfg, used_url = fetch_discovery(http, target, rep)
    rep.meta["discovery_url"] = used_url
    if cfg is None:
        rep.add("INFO", "no-config",
                "Could not retrieve/parse a discovery document (tried OIDC and "
                "RFC 8414 locations); aborting.", location=used_url)
        return rep

    rep.meta["endpoints"] = {k: cfg.get(k) for k in ENDPOINT_KEYS if cfg.get(k)}

    check_issuer(cfg, used_url, rep)
    check_https_endpoints(cfg, rep)
    check_algorithms(cfg, rep)
    check_pkce(cfg, rep)
    check_grants_and_responses(cfg, rep)
    check_auth_methods(cfg, rep)
    check_request_object(cfg, rep)
    check_misc(cfg, rep)

    if tls_check:
        host = urlparse(cfg.get("issuer") or used_url).hostname
        port = urlparse(cfg.get("issuer") or used_url).port or 443
        if host:
            check_tls(host, port, rep, http.timeout, verify=http.verify)

    jwks_uri = cfg.get("jwks_uri")
    if jwks_uri:
        if fetch_jwks:
            jwks, _ = fetch_json(http, jwks_uri, rep, "JWKS")
            if jwks is not None:
                check_jwks(jwks, rep, jwks_uri, cfg)
        else:
            rep.add("INFO", "jwks-skipped",
                    "jwks_uri present but JWKS fetch disabled (--no-jwks).",
                    location=jwks_uri)
    else:
        rep.add("MEDIUM", "jwks-missing", "No jwks_uri advertised.")

    if probe:
        for key, url in rep.meta["endpoints"].items():
            if key == "jwks_uri":
                continue
            probe_endpoint(http, key, url, rep)
        if cfg.get("issuer"):
            probe_webfinger(http, cfg["issuer"], rep)
        if dynreg and cfg.get("registration_endpoint"):
            probe_dynamic_registration(http, cfg["registration_endpoint"], rep)

    return rep


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def c(text, sev, use_color):
    return f"{COLORS.get(sev,'')}{text}{COLORS['RESET']}" if use_color else text


def print_report(rep, use_color=True, verbose=False):
    print(c(f"\n=== OIDC audit: {rep.meta.get('discovery_url')} ===",
            "BOLD", use_color))
    if rep.meta.get("issuer"):
        print(f"  issuer:  {rep.meta['issuer']}")
    eps = rep.meta.get("endpoints", {})
    if eps:
        print(f"  endpoints advertised: {len(eps)}")
        if verbose:
            for k, v in eps.items():
                print(f"      {k}: {v}")
    if "jwks_key_count" in rep.meta:
        print(f"  jwks keys: {rep.meta['jwks_key_count']}")
    for host, t in (rep.meta.get("tls") or {}).items():
        exp = t.get("days_to_expiry")
        print(f"  tls[{host}]: {t.get('protocol')}"
              + (f", cert expires in {exp:.0f}d" if exp is not None else ""))

    counts = {}
    for f in rep.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = "  ".join(c(f"{s}:{counts.get(s,0)}", s, use_color)
                        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    n_manual = sum(1 for f in rep.findings if f["manual"])
    print("\n  " + summary
          + (c(f"   (manual-verify: {n_manual})", "MANUAL", use_color)
             if n_manual else "") + "\n")

    findings = [f for f in rep.sorted_findings()
                if verbose or f["severity"] != "INFO"]
    if not findings:
        print(c("  No issues at/above LOW. (use -v for INFO)", "OK", use_color))

    pad = " " * 13

    def field(label, value, color="LABEL"):
        if value:
            print(f"{pad}" + c(f"{label}:", color, use_color) + f" {value}")

    for f in findings:
        tag = c(f"[{f['severity']:^8}]", f["severity"], use_color)
        print(f"  {tag} {f['title']}")
        if f["detail"]:
            print(f"{pad}{f['detail']}")
        where = f.get("pointer", "")
        loc = f.get("location", "")
        if where:
            line = f"{pad}" + c("where:", "LABEL", use_color) + " " \
                   + c(where, "BOLD", use_color) + (f"   in {loc}" if loc else "")
            print(line)
        elif loc:
            field("where", loc)
        field("evidence", f.get("evidence"))
        field("impact", f.get("impact"))
        field("fix", f.get("recommendation"))
        if f["manual"]:
            print(pad + c("→ manual verification required "
                          "(surface only; confirm with live testing)",
                          "MANUAL", use_color))
        print()


def report_to_dict(rep):
    return {"target": rep.meta.get("discovery_url"),
            "meta": rep.meta,
            "findings": rep.sorted_findings()}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_headers(items):
    out = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Audit public OIDC discovery documents for common "
                    "misconfigurations and risks.",
        epilog="Only run against systems you are authorized to test.")
    ap.add_argument("url", nargs="?",
                    help="Issuer, base URL, or full discovery URL")
    ap.add_argument("-f", "--targets-file",
                    help="File with one target per line (# comments allowed)")
    ap.add_argument("--probe", action="store_true",
                    help="Visit advertised endpoints + WebFinger (read-only GET).")
    ap.add_argument("--dynamic-reg-probe", action="store_true",
                    help="INTRUSIVE: attempt unauthenticated Dynamic Client "
                         "Registration (POST). Requires --probe.")
    ap.add_argument("--no-jwks", action="store_true",
                    help="Do not fetch/analyze the JWKS (fetched by default).")
    ap.add_argument("--no-tls-check", action="store_true",
                    help="Skip the issuer TLS/certificate handshake inspection.")
    ap.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Do not verify TLS certificates for requests")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("-H", "--header", action="append",
                    help="Extra header 'Name: value' (repeatable)")
    ap.add_argument("-A", "--user-agent", help="Custom User-Agent")
    ap.add_argument("--json", action="store_true", help="Emit JSON")
    ap.add_argument("-o", "--output", help="Write report to file")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Show INFO findings and endpoint/location detail")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.targets_file:
        with open(args.targets_file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    if not targets:
        ap.error("provide a URL or --targets-file")
    if args.dynamic_reg_probe and not args.probe:
        ap.error("--dynamic-reg-probe requires --probe")

    http = Http(timeout=args.timeout, verify=not args.insecure, proxy=args.proxy,
                headers=parse_headers(args.header), ua=args.user_agent)

    use_color = sys.stdout.isatty() and not args.no_color
    reports = []
    for t in targets:
        rep = audit(t, http, probe=args.probe, dynreg=args.dynamic_reg_probe,
                    fetch_jwks=not args.no_jwks, tls_check=not args.no_tls_check)
        reports.append(rep)
    if len(reports) > 1:
        flag_cross_target_keys(reports)
    if not args.json:
        for rep in reports:
            print_report(rep, use_color=use_color, verbose=args.verbose)

    out_text = (json.dumps([report_to_dict(r) for r in reports], indent=2)
                if args.json else None)
    if args.json and not args.output:
        print(out_text)
    if args.output:
        with open(args.output, "w") as fh:
            if args.json:
                fh.write(out_text)
            else:
                buf, _stdout = io.StringIO(), sys.stdout
                sys.stdout = buf
                for r in reports:
                    print_report(r, use_color=False, verbose=args.verbose)
                sys.stdout = _stdout
                fh.write(buf.getvalue())
        sys.stderr.write(f"[+] report written to {args.output}\n")

    worst = 9
    for r in reports:
        for f in r.findings:
            worst = min(worst, SEV_ORDER.get(f["severity"], 9))
    sys.exit(0 if worst >= SEV_ORDER["LOW"] else 1)


if __name__ == "__main__":
    main()
