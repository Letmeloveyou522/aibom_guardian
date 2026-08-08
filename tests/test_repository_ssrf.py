"""
test_repository_ssrf.py
-----------------------------------
Unit tests for repository_checker's SSRF defence.

    python3 -m pytest tests/test_repository_ssrf.py -q

repository_checker.py is a third of the codebase and had the lowest test
density in it. `validate_public_url` is the function that decides whether a
URL taken from package metadata - which an attacker can set - is allowed to
be requested at all, so a hole here turns the scanner into a request proxy
for whoever publishes a package. Nothing pinned it.

Every test here is offline: DNS is stubbed so the allowlist, the scheme and
port rules, and the rebinding defence are exercised without leaving the
machine.
"""

import ipaddress
import socket

import pytest

import repository_checker
from repository_checker import SSRFError, validate_public_url


@pytest.fixture
def resolves_to(monkeypatch):
    """Point every DNS lookup at a chosen address."""

    def _set(address):
        family = (socket.AF_INET6 if ":" in address else socket.AF_INET)

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(family, socket.SOCK_STREAM, 6, "", (address, port or 443))]

        monkeypatch.setattr(repository_checker.socket, "getaddrinfo",
                            fake_getaddrinfo)

    return _set


# ---------------------------------------------------------------------------
# What must be allowed - over-blocking breaks every scan
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://github.com/pallets/flask",
    "https://api.github.com/repos/pallets/flask",
    "https://raw.githubusercontent.com/pallets/flask/main/README.md",
    "https://huggingface.co/google-bert/bert-base-uncased",
    "https://pypi.org/pypi/requests/json",
    "https://api.securityscorecards.dev/projects/github.com/pallets/flask",
])
def test_allowlisted_hosts_pass(url, resolves_to):
    resolves_to("140.82.121.4")
    assert validate_public_url(url)


def test_an_ipv6_only_network_still_reaches_github(resolves_to):
    """
    On NAT64, github.com resolves to 64:ff9b::14c8:f5f7 - a real GitHub
    address that `ipaddress` reports as is_reserved. Rejecting it outright
    made every lookup fail on IPv6-only networks.
    """
    resolves_to("64:ff9b::14c8:f5f7")
    assert validate_public_url("https://github.com/pallets/flask")


# ---------------------------------------------------------------------------
# What must be refused
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,reason", [
    ("http://github.com/x", "plain http"),
    ("file:///etc/passwd", "file scheme"),
    ("ftp://github.com/x", "ftp scheme"),
    ("gopher://github.com/x", "gopher scheme"),
    ("//github.com/x", "no scheme"),
    ("", "empty"),
])
def test_only_https_is_accepted(url, reason, resolves_to):
    resolves_to("140.82.121.4")
    with pytest.raises(SSRFError):
        validate_public_url(url)


def test_hosts_outside_the_allowlist_are_refused(resolves_to):
    resolves_to("140.82.121.4")
    for url in ["https://evil.example.com/x",
                "https://github.com.evil.example.com/x",
                "https://notgithub.com/x"]:
        with pytest.raises(SSRFError):
            validate_public_url(url)


def test_localhost_is_refused(resolves_to):
    resolves_to("127.0.0.1")
    for host in ("localhost", "localhost.localdomain"):
        with pytest.raises(SSRFError):
            validate_public_url(f"https://{host}/x")


def test_credentials_in_the_url_are_refused(resolves_to):
    """
    userinfo is how a redirect gets pointed somewhere else while still
    looking like an allowlisted host.
    """
    resolves_to("140.82.121.4")
    with pytest.raises(SSRFError):
        validate_public_url("https://user:pass@github.com/x")


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/x",
    "https://169.254.169.254/latest/meta-data/",   # cloud metadata
    "https://10.0.0.1/x",
    "https://192.168.1.1/x",
    "https://[::1]/x",
])
def test_raw_ip_addresses_are_refused(url, resolves_to):
    resolves_to("140.82.121.4")
    with pytest.raises(SSRFError):
        validate_public_url(url)


def test_non_standard_ports_are_refused(resolves_to):
    resolves_to("140.82.121.4")
    for port in (8080, 22, 3306, 6379):
        with pytest.raises(SSRFError):
            validate_public_url(f"https://github.com:{port}/x")


def test_path_traversal_is_refused(resolves_to):
    resolves_to("140.82.121.4")
    with pytest.raises(SSRFError):
        validate_public_url("https://github.com/a/../../etc/passwd")


# ---------------------------------------------------------------------------
# DNS rebinding: the name is allowlisted, the answer is not
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address,what", [
    ("127.0.0.1", "loopback"),
    ("169.254.169.254", "cloud metadata"),
    ("10.1.2.3", "private"),
    ("192.168.0.5", "private"),
    ("172.16.0.1", "private"),
    ("0.0.0.0", "unspecified"),
    ("::1", "IPv6 loopback"),
    ("fd00::1", "IPv6 private"),
    ("64:ff9b::7f00:1", "NAT64-wrapped loopback"),
    ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
])
def test_an_allowlisted_host_resolving_somewhere_private_is_refused(
        address, what, resolves_to):
    """
    The allowlist is checked against the name; the answer decides where the
    request actually goes. An attacker who controls DNS for an allowlisted
    name - or a machine with a poisoned resolver - would otherwise get the
    scanner to fetch link-local metadata on their behalf.
    """
    resolves_to(address)
    with pytest.raises(SSRFError):
        validate_public_url("https://github.com/pallets/flask")


def test_the_nat64_unwrapping_does_not_widen_the_hole():
    """
    Unwrapping NAT64 was added so IPv6-only networks work. The embedded IPv4
    has to go through the same checks, or the wrapper becomes a bypass.
    """
    blocked = repository_checker._is_blocked_ip
    assert blocked(ipaddress.ip_address("64:ff9b::7f00:1"))        # 127.0.0.1
    assert blocked(ipaddress.ip_address("64:ff9b::a9fe:a9fe"))     # 169.254.169.254
    assert blocked(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert not blocked(ipaddress.ip_address("64:ff9b::14c8:f5f7"))  # 20.200.245.247


def test_dns_failure_is_an_error_not_a_pass(monkeypatch):
    """A name that will not resolve must not fall through as allowed."""
    def boom(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(repository_checker.socket, "getaddrinfo", boom)
    with pytest.raises(SSRFError):
        validate_public_url("https://github.com/pallets/flask")
