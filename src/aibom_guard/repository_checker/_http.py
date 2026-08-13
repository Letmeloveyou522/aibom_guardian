"""
SSRF guard and the HTTP client that enforces it.

URLs come from package metadata, so they are attacker-controlled. Every
request goes through SafeHTTPClient, which requires https, an allow-listed
host, an allowed port, no userinfo and no raw IP literal, then resolves the
host and rejects private, loopback or link-local answers - unwrapping
IPv4-in-IPv6 first so NAT64 networks still work. Redirects repeat all of it.

Known limit: requests resolves DNS again when it connects, so a
time-of-check/time-of-use window remains. Closing it needs an adapter that
connects to the validated address while keeping SNI and cert verification on
the hostname; not implemented. The host allow-list is what keeps the residual
risk small.

Bypasses are covered by tests/test_repository_ssrf.py.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from typing import Any

from ._constants import (
    ALLOWED_HOSTS,
    ALLOWED_HTTP_PORTS,
    ALLOWED_PORTS,
    REDIRECT_MAX,
    USER_AGENT,
)
from ._helpers import _error

logger = logging.getLogger(__name__)


class SSRFError(ValueError):
    """Raised when a URL fails SSRF validation."""


# RFC 6052 well-known prefix used by NAT64/DNS64 to reach IPv4 hosts from an
# IPv6-only network. Addresses inside it report is_reserved=True even though
# the IPv4 they carry is perfectly public.
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """
    Return the IPv4 address an IPv6 address actually carries, if any.

    Covers IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) forms.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # On an IPv6-only / NAT64 network, github.com resolves to something like
    # 64:ff9b::14c8:f5f7 - which is 20.200.245.247, a real GitHub address, but
    # which ipaddress reports as is_reserved. Without this unwrapping every
    # GitHub and Hugging Face lookup fails as "not publicly routable".
    #
    # This does not weaken the SSRF defense: the embedded IPv4 is run through
    # exactly the same checks, so 64:ff9b::7f00:1 (127.0.0.1) is still blocked.
    embedded = _embedded_ipv4(ip) if isinstance(ip, ipaddress.IPv6Address) else None
    if embedded is not None:
        return _is_blocked_ip(embedded)

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_public_url(url: str, *, allow_http: bool = False) -> str:
    """
    Validate that ``url`` is safe to request (SSRF defense).
    Returns the normalized URL string on success.
    """
    if not url or not isinstance(url, str):
        raise SSRFError("empty or invalid URL")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",) and not (allow_http and scheme == "http"):
        raise SSRFError(f"disallowed URL scheme: {scheme or '<none>'}")

    if parsed.username or parsed.password:
        raise SSRFError("URL must not contain userinfo credentials")

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise SSRFError("URL missing host")

    if host in ("localhost", "localhost.localdomain"):
        raise SSRFError("localhost is not allowed")

    if host not in ALLOWED_HOSTS:
        raise SSRFError(f"host not in allowlist: {host}")

    # .port raises a plain ValueError for ":99999" or ":notaport". Callers
    # catch SSRFError, which is a *subclass* of ValueError, so an unwrapped one
    # would escape them and abort the scan instead of refusing the URL.
    try:
        port = parsed.port
    except ValueError as exc:
        raise SSRFError(f"invalid port in URL: {exc}") from exc

    allowed_ports = ALLOWED_PORTS | (ALLOWED_HTTP_PORTS if allow_http else frozenset())
    if port not in allowed_ports:
        raise SSRFError(f"disallowed port: {port}")

    # Block literal IPs even if somehow in allowlist
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            raise SSRFError(f"blocked IP address: {host}")
        raise SSRFError(f"raw IP addresses are not allowed: {host}")
    except ValueError:
        pass  # hostname, not IP

    # Resolve DNS and reject private/link-local answers (DNS rebinding defense)
    try:
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise SSRFError(f"resolved address is not publicly routable: {addr}")

    path = parsed.path or ""
    if ".." in path.split("/"):
        raise SSRFError("path traversal is not allowed in URL path")

    return parsed.geturl() if parsed.geturl().startswith("http") else url.strip()


def _build_session(timeout: float) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.request_timeout = timeout  # type: ignore[attr-defined]
    return session


class SafeHTTPClient:
    """HTTP client with SSRF checks, redirect re-validation, and retries."""

    def __init__(
        self,
        timeout: float = 10.0,
        default_headers: dict | None = None,
    ):
        self.timeout = timeout
        self.session = _build_session(timeout)
        self.default_headers = default_headers or {"User-Agent": USER_AGENT}
        self._cache: dict[str, Any] = {}

    def get_json(
        self,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        cache_key: str | None = None,
        allow_statuses: tuple[int, ...] = (200,),
    ) -> tuple[Any | None, requests.Response | None, dict | None]:
        """
        GET JSON safely.

        Returns (data, response, error_dict).
        On expected API failures, data may be None and error_dict set.
        """
        if cache_key and cache_key in self._cache:
            return self._cache[cache_key]

        try:
            validate_public_url(url)
        except SSRFError as exc:
            err = _error("http", "ssrf_blocked", str(exc), retryable=False)
            return None, None, err

        merged = dict(self.default_headers)
        if headers:
            # Never log Authorization; just merge for the request.
            merged.update(headers)

        try:
            response = self._get_with_redirects(url, merged, params)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)
        except requests.exceptions.Timeout:
            return None, None, _error("http", "timeout", f"request timed out: {urlparse(url).netloc}", True)
        except requests.exceptions.RequestException as exc:
            return None, None, _error("http", "network", f"request failed: {type(exc).__name__}", True)

        if response.status_code not in allow_statuses and response.status_code not in (200,):
            # Caller may still want the response for 404 handling
            pass

        data = None
        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                return None, response, _error("http", "invalid_json", "response was not valid JSON", False)

        result = (data, response, None)
        if cache_key and response.status_code == 200:
            self._cache[cache_key] = result
        return result

    def get_text(
        self,
        url: str,
        *,
        headers: dict | None = None,
        cache_key: str | None = None,
    ) -> tuple[str | None, requests.Response | None, dict | None]:
        try:
            validate_public_url(url)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)

        merged = dict(self.default_headers)
        if headers:
            merged.update(headers)

        try:
            response = self._get_with_redirects(url, merged, None)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)
        except requests.exceptions.Timeout:
            return None, None, _error("http", "timeout", "request timed out", True)
        except requests.exceptions.RequestException as exc:
            return None, None, _error("http", "network", f"request failed: {type(exc).__name__}", True)

        if response.status_code != 200:
            return None, response, None

        text = response.text
        result = (text, response, None)
        if cache_key:
            self._cache[cache_key] = result
        return result

    def _get_with_redirects(
        self,
        url: str,
        headers: dict,
        params: dict | None,
    ) -> requests.Response:
        current = validate_public_url(url)
        for _ in range(REDIRECT_MAX + 1):
            response = self.session.get(
                current,
                headers=headers,
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
            )
            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return response
                next_url = urljoin(current, location)
                current = validate_public_url(next_url)
                params = None  # params already applied on first hop
                continue
            return response
        raise SSRFError("too many redirects")
