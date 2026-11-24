"""One SSRF address classifier for every network-facing lane.

The browser, web research, the isolated crawler and the Operator's HTTP tool
all used slightly different checks. ``ipaddress.is_private`` does not cover
carrier-grade NAT (100.64.0.0/10), multicast or IPv4-mapped IPv6 addresses on
every Python version, so those lanes could disagree. This module is the single
definition of "public enough to fetch".

It is intentionally conservative: a hostname is public only when *every*
resolved address is public, and DNS failures are treated as non-public.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit

# IPv4 addresses embedded in these IPv6 prefixes must be judged by the
# embedded address; ipaddress marks some of them global.
_EMBEDDED_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),      # NAT64 well-known prefix
    ipaddress.ip_network("64:ff9b:1::/48"),    # local-use NAT64
    ipaddress.ip_network("2002::/16"),         # 6to4
)


def is_public_ip(value) -> bool:
    """True only for a globally routable unicast address."""
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except (TypeError, ValueError):
        return False
    if address.version == 6:
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if any(address in network for network in _EMBEDDED_PREFIXES):
            return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_multicast
        and not address.is_unspecified
    )


def resolved_public_ips(host: str) -> list[str]:
    """All resolved addresses, or [] when any answer is non-public/unresolvable."""
    host = str(host or "").strip("[]").lower()
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        if not is_public_ip(raw):
            return []
        addresses.append(raw)
    return list(dict.fromkeys(addresses))


def is_public_host(host: str) -> bool:
    host = str(host or "").strip("[]").lower()
    if not host or host == "localhost" or host.endswith(".localhost") \
            or host.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return bool(resolved_public_ips(host))
    return is_public_ip(address)


def public_ip(host: str) -> str | None:
    """First public address for *host*, failing closed on mixed/private DNS."""
    host = str(host or "").strip("[]").lower()
    if not host:
        return None
    try:
        address = ipaddress.ip_address(host)
        return str(address) if is_public_ip(address) else None
    except ValueError:
        pass
    addresses = resolved_public_ips(host)
    return addresses[0] if addresses else None


def is_public_url(url: str) -> bool:
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return is_public_host(parsed.hostname)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to the validated IP once, not to a second DNS answer."""

    def __init__(self, *args, allow_private: bool = False, peer_validator=None, **kwargs):
        self.allow_private = bool(allow_private)
        self.peer_validator = peer_validator
        super().__init__(*args, **kwargs)

    def _resolve_peer(self, host: str) -> str:
        if self.allow_private:
            return host
        if self.peer_validator is not None:
            return self.peer_validator(host)
        address = public_ip(host)
        if address is None:
            raise OSError(f"refusing non-public address for {host}")
        return address

    def connect(self):
        address = self._resolve_peer(self.host)
        self.sock = socket.create_connection((address, self.port), self.timeout)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS variant: connect to the validated IP, verify TLS against the hostname."""

    def __init__(self, *args, allow_private: bool = False, peer_validator=None, **kwargs):
        self.allow_private = bool(allow_private)
        self.peer_validator = peer_validator
        super().__init__(*args, **kwargs)

    def _resolve_peer(self, host: str) -> str:
        if self.allow_private:
            return host
        if self.peer_validator is not None:
            return self.peer_validator(host)
        address = public_ip(host)
        if address is None:
            raise OSError(f"refusing non-public address for {host}")
        return address

    def connect(self):
        hostname = self.host
        address = self._resolve_peer(hostname)
        sock = socket.create_connection((address, self.port), self.timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        context = getattr(self, "_context", None) or ssl.create_default_context()
        self.sock = context.wrap_socket(sock, server_hostname=hostname)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, allow_private: bool = False, peer_validator=None):
        super().__init__()
        self.allow_private = bool(allow_private)
        self.peer_validator = peer_validator

    def http_open(self, request):
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPConnection(
                host, allow_private=self.allow_private,
                peer_validator=self.peer_validator, **kwargs), request)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, allow_private: bool = False, peer_validator=None):
        super().__init__()
        self.allow_private = bool(allow_private)
        self.peer_validator = peer_validator

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPSConnection(
                host, allow_private=self.allow_private,
                peer_validator=self.peer_validator, **kwargs), request)

