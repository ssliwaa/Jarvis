"""Non-destructive network diagnostic operator module for Jarvis.

Provides TCP reachability probing, latency measurement, DNS forward/reverse resolution,
TLS certificate auditing, and raw socket HTTP HEAD status verification using exclusively
the Python standard library.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import time
import urllib.parse
from typing import Any

DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 10.0
MIN_TIMEOUT = 0.1
DEFAULT_COUNT = 1
MAX_COUNT = 10
MAX_HEADER_BYTES = 65536  # 64 KB

REDACTED_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
    "token",
    "x-auth-token",
})

VALID_ACTIONS = frozenset({"tcp_ping", "dns_lookup", "cert_inspect", "http_head"})
VALID_QUERY_TYPES = frozenset({"A", "AAAA", "CNAME", "PTR", "ALL"})
KNOWN_ARGUMENTS = frozenset({
    "action",
    "host",
    "port",
    "timeout",
    "timeout_seconds",
    "count",
    "query_type",
    "record_type",
    "path",
    "use_tls",
    "allow_private",
    "server_name",
    "verify_peer",
})


def _envelope(ok: bool, data: Any = None, error: str | None = None) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator envelope."""
    if ok:
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}
    return {"ok": False, "success": False, "data": None, "result": None, "error": error}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive authorization or session headers."""
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in REDACTED_HEADERS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def _is_private_or_local(ip_str: str) -> bool:
    """Check whether an IP address is private, loopback, link-local, or non-global."""
    try:
        clean = ip_str.split("%")[0].strip("[]")
        addr = ipaddress.ip_address(clean)
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
            or not addr.is_global
        )
    except ValueError:
        return False


def _format_rdn_sequence(seq: Any) -> dict[str, str]:
    """Format an X.509 RDN tuple-of-tuples into a clean dictionary."""
    out: dict[str, str] = {}
    if not seq:
        return out
    for rdn in seq:
        for k, v in rdn:
            out[str(k)] = str(v)
    return out


def _parse_cert_date(date_str: str | None) -> tuple[str | None, datetime.datetime | None]:
    """Parse SSL date string to ISO 8601 string and timezone-aware UTC datetime."""
    if not date_str:
        return None, None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            dt = datetime.datetime.strptime(date_str, fmt).replace(tzinfo=datetime.timezone.utc)
            return dt.isoformat(), dt
        except ValueError:
            pass
    return date_str, None


def _resolve_target_ip(host: str, port: int, allow_private: bool) -> tuple[str, int, int]:
    """Resolve target host and port to (ip, family, port), enforcing SSRF guardrail."""
    clean_host = host.strip("[]")
    try:
        infos = socket.getaddrinfo(clean_host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise socket.gaierror(err.errno, f"DNS resolution failed for '{clean_host}': {err}") from err

    if not infos:
        raise socket.gaierror(socket.EAI_NONAME, f"No address records found for '{clean_host}'")

    family, _, _, _, sockaddr = infos[0]
    ip = str(sockaddr[0]).split("%")[0]

    if not allow_private and _is_private_or_local(ip):
        raise ValueError(f"SSRFSecurityError: Target address '{ip}' is a private/loopback destination (pass allow_private=True to permit).")

    return ip, family, port


def _do_tcp_ping(host: str, port: int, timeout: float, count: int, allow_private: bool) -> dict[str, Any]:
    """Execute TCP reachability and latency probe."""
    ip, family, _ = _resolve_target_ip(host, port, allow_private)
    is_priv = _is_private_or_local(ip)

    probes = []
    successes: list[float] = []

    for seq in range(1, count + 1):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t_start = time.monotonic()
        try:
            sock.connect((ip, port))
            t_end = time.monotonic()
            lat = round((t_end - t_start) * 1000.0, 2)
            probes.append({"seq": seq, "success": True, "latency_ms": lat, "error": None})
            successes.append(lat)
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as exc:
            probes.append({"seq": seq, "success": False, "latency_ms": None, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

        if seq < count:
            time.sleep(0.05)

    connected = len(successes) > 0
    loss_rate = round((count - len(successes)) / count, 2)
    packet_loss_pct = round(loss_rate * 100.0, 1)

    min_lat = min(successes) if successes else None
    max_lat = max(successes) if successes else None
    avg_lat = round(sum(successes) / len(successes), 2) if successes else None

    return {
        "host": host,
        "ip": ip,
        "port": port,
        "connected": connected,
        "reachable": connected,
        "latency_ms": avg_lat,
        "min_latency_ms": min_lat,
        "latency_ms_min": min_lat,
        "avg_latency_ms": avg_lat,
        "latency_ms_avg": avg_lat,
        "max_latency_ms": max_lat,
        "latency_ms_max": max_lat,
        "count": count,
        "packets_transmitted": count,
        "packets_received": len(successes),
        "loss_rate": loss_rate,
        "packet_loss_pct": packet_loss_pct,
        "latencies_ms": successes,
        "is_private": is_priv,
        "is_loopback": ip in ("127.0.0.1", "::1"),
        "probes": probes,
    }


def _do_dns_lookup(host: str, query_type: str, timeout: float, allow_private: bool) -> dict[str, Any]:
    """Execute DNS resolution diagnostics."""
    del timeout
    t0 = time.monotonic()

    if query_type == "PTR":
        try:
            ip_obj = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            raise ValueError(f"For PTR lookup, host must be a valid IPv4 or IPv6 address, got '{host}'.")

        ip_str = str(ip_obj)
        if not allow_private and _is_private_or_local(ip_str):
            raise ValueError(f"SSRFSecurityError: Target address '{ip_str}' is a private/loopback destination (pass allow_private=True to permit).")

        try:
            canonical_name, aliases, _ = socket.gethostbyaddr(ip_str)
        except (socket.herror, socket.gaierror, OSError) as exc:
            raise socket.gaierror(socket.EAI_NONAME, f"Reverse DNS lookup failed for '{host}': {exc}") from exc

        t1 = time.monotonic()
        return {
            "host": host,
            "query_type": "PTR",
            "record_type": "PTR",
            "canonical_name": canonical_name,
            "aliases": list(aliases),
            "records": [canonical_name],
            "latency_ms": round((t1 - t0) * 1000.0, 2),
        }

    ipv4_list: list[str] = []
    ipv6_list: list[str] = []
    canonical_name = host
    aliases: list[str] = []

    if query_type in ("A", "ALL"):
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            for info in infos:
                raw_ip = str(info[4][0])
                if raw_ip not in ipv4_list:
                    ipv4_list.append(raw_ip)
        except socket.gaierror:
            pass

    if query_type in ("AAAA", "ALL"):
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET6, type=socket.SOCK_STREAM)
            for info in infos:
                raw_ip = str(info[4][0]).split("%")[0]
                if raw_ip not in ipv6_list:
                    ipv6_list.append(raw_ip)
        except socket.gaierror:
            pass

    if query_type in ("CNAME", "ALL"):
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, flags=socket.AI_CANONNAME)
            for info in infos:
                if info[3]:
                    canonical_name = info[3]
                    break
        except socket.gaierror:
            pass
        try:
            _, alias_list, _ = socket.gethostbyname_ex(host)
            aliases = [a for a in alias_list if a != host and a != canonical_name]
        except (socket.gaierror, OSError):
            pass

    total_addresses = ipv4_list + ipv6_list
    if not total_addresses and query_type != "CNAME":
        raise socket.gaierror(socket.EAI_NONAME, f"Name or service not known: '{host}'")

    if not allow_private and any(_is_private_or_local(ip) for ip in total_addresses):
        bad_ips = [ip for ip in total_addresses if _is_private_or_local(ip)]
        raise ValueError(f"SSRFSecurityError: Target address '{bad_ips[0]}' is a private/loopback destination (pass allow_private=True to permit).")

    t1 = time.monotonic()
    return {
        "host": host,
        "query_type": query_type,
        "record_type": query_type,
        "canonical_name": canonical_name,
        "aliases": aliases,
        "ipv4": ipv4_list,
        "ipv6": ipv6_list,
        "addresses": total_addresses,
        "latency_ms": round((t1 - t0) * 1000.0, 2),
    }


def _do_cert_inspect(
    host: str,
    port: int,
    timeout: float,
    server_name: str | None,
    verify_peer: bool,
    allow_private: bool,
) -> dict[str, Any]:
    """Execute TLS peer certificate inspection."""
    ip, _, _ = _resolve_target_ip(host, port, allow_private)
    sni_host = server_name or host

    ctx = ssl.create_default_context()
    if not verify_peer:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    t0 = time.monotonic()
    raw_sock = socket.create_connection((ip, port), timeout=timeout)
    ssock = None
    try:
        ssock = ctx.wrap_socket(raw_sock, server_hostname=sni_host)
        t1 = time.monotonic()
        handshake_ms = round((t1 - t0) * 1000.0, 2)

        tls_version = ssock.version()
        cipher = list(ssock.cipher() or ())
        cert = ssock.getpeercert()

        now = datetime.datetime.now(datetime.timezone.utc)
        valid_from_iso, _ = _parse_cert_date(cert.get("notBefore") if cert else None)
        valid_until_iso, dt_until = _parse_cert_date(cert.get("notAfter") if cert else None)

        days_remaining = None
        expired = False
        if dt_until is not None:
            days_remaining = int(round((dt_until - now).total_seconds() / 86400))
            expired = now > dt_until

        sans = [entry[1] for entry in cert.get("subjectAltName", ())] if cert else []
        subject_dict = _format_rdn_sequence(cert.get("subject")) if cert else {}
        issuer_dict = _format_rdn_sequence(cert.get("issuer")) if cert else {}

        raw_pem = None
        if not cert and not verify_peer:
            der = ssock.getpeercert(binary_form=True)
            if der:
                raw_pem = ssl.DER_cert_to_PEM_cert(der)

        out: dict[str, Any] = {
            "host": host,
            "port": port,
            "tls_version": tls_version,
            "cipher": cipher,
            "subject": subject_dict,
            "issuer": issuer_dict,
            "valid_from": valid_from_iso,
            "valid_until": valid_until_iso,
            "days_remaining": days_remaining,
            "expired": expired,
            "subject_alt_names": sans,
            "serial_number": cert.get("serialNumber") if cert else None,
            "handshake_latency_ms": handshake_ms,
            "latency_ms": handshake_ms,
        }
        if raw_pem:
            out["raw_pem"] = raw_pem
        return out
    finally:
        if ssock is not None:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            ssock.close()
        else:
            try:
                raw_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            raw_sock.close()


def _do_http_head(
    host: str,
    port: int,
    path: str,
    use_tls: bool,
    timeout: float,
    server_name: str | None,
    verify_peer: bool,
    allow_private: bool,
) -> dict[str, Any]:
    """Execute raw socket HTTP HEAD probe."""
    # 1. Reject CRLF / NULL control characters in path
    if any(c in path for c in ("\r", "\n", "\x00")):
        raise ValueError("Parameter 'path' must not contain CR, LF, or NULL control characters.")

    if not path.startswith("/"):
        path = "/" + path

    # 2. Safely quote path
    quoted_path = urllib.parse.quote(path, safe="/:?#[]@!$&'()*+,;=")

    # 3. Safely encode IDN hosts
    try:
        clean_host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        clean_host = host

    target_sni = server_name or host
    try:
        clean_sni = target_sni.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        clean_sni = target_sni
    sni_host = clean_sni

    ip, _, _ = _resolve_target_ip(clean_host, port, allow_private)

    host_hdr = clean_host if (port in (80, 443)) else f"{clean_host}:{port}"
    request_data = (
        f"HEAD {quoted_path} HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"User-Agent: Jarvis-NetProbe/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    t0 = time.monotonic()
    deadline = t0 + timeout
    raw_sock = socket.create_connection((ip, port), timeout=timeout)
    active_sock = raw_sock

    try:
        if use_tls:
            tls_remaining = deadline - time.monotonic()
            if tls_remaining <= 0:
                raise TimeoutError(f"HTTP HEAD request exceeded timeout limit of {timeout}s.")
            raw_sock.settimeout(max(0.01, tls_remaining))

            ctx = ssl.create_default_context()
            if not verify_peer:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            active_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_host)

        send_remaining = deadline - time.monotonic()
        if send_remaining <= 0:
            raise TimeoutError(f"HTTP HEAD request exceeded timeout limit of {timeout}s.")
        active_sock.settimeout(max(0.01, send_remaining))

        active_sock.sendall(request_data)

        buf = bytearray()
        delimiter = b"\r\n\r\n"

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"HTTP HEAD request timed out after {timeout} seconds.")
            active_sock.settimeout(max(0.01, remaining))

            chunk = active_sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if delimiter in buf or b"\n\n" in buf:
                break
            if len(buf) > MAX_HEADER_BYTES:
                raise ValueError(f"HTTP headers exceeded maximum limit of {MAX_HEADER_BYTES} bytes.")

        t1 = time.monotonic()
        latency_ms = round((t1 - t0) * 1000.0, 2)

        raw_head = bytes(buf).split(b"\r\n\r\n", 1)[0]
        if b"\r\n\r\n" not in buf and b"\n\n" in buf:
            raw_head = bytes(buf).split(b"\n\n", 1)[0]

        head_text = raw_head.decode("iso-8859-1")
        lines = head_text.splitlines()

        if not lines:
            raise ConnectionResetError("Server closed connection without returning HTTP headers.")

        status_line = lines[0].strip()
        status_parts = status_line.split(" ", 2)
        http_version = status_parts[0]
        status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0
        status_text = status_parts[2] if len(status_parts) > 2 else ""

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        return {
            "host": host,
            "port": port,
            "path": path,
            "use_tls": use_tls,
            "status_code": status_code,
            "status_text": status_text,
            "reason": status_text,
            "http_version": http_version,
            "protocol": http_version,
            "headers": _redact_headers(headers),
            "latency_ms": latency_ms,
            "bytes_read": len(buf),
        }
    finally:
        try:
            active_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        active_sock.close()


def net_probe(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute non-destructive network reachability, DNS, TLS, or HTTP HEAD probe."""
    del context
    if not isinstance(arguments, dict):
        return _envelope(False, None, error="ValueError: Arguments must be a dictionary.")

    try:
        # Enforce additionalProperties: False
        extra = set(arguments.keys()) - KNOWN_ARGUMENTS
        if extra:
            raise ValueError(f"Unexpected argument(s): {', '.join(sorted(extra))}")

        action = arguments.get("action")
        if not action or not isinstance(action, str) or action not in VALID_ACTIONS:
            raise ValueError(
                f"Unsupported or missing action: {action!r}. Supported actions: {sorted(VALID_ACTIONS)}"
            )

        raw_host = arguments.get("host")
        if not isinstance(raw_host, str) or not raw_host.strip():
            raise ValueError("Parameter 'host' must be a non-empty string hostname or IP address.")

        host = raw_host.strip()
        if "://" in host:
            parsed = urllib.parse.urlsplit(host)
            host = (parsed.hostname or "").strip("[]")
            if not host:
                raise ValueError("Parameter 'host' contains an invalid URL structure without a hostname.")

        # Timeout handling (supports 'timeout' or 'timeout_seconds')
        timeout_val = arguments.get("timeout_seconds") if "timeout_seconds" in arguments else arguments.get("timeout", DEFAULT_TIMEOUT)
        if isinstance(timeout_val, bool) or not isinstance(timeout_val, (int, float)):
            raise ValueError(f"Parameter 'timeout' must be a number between {MIN_TIMEOUT} and {MAX_TIMEOUT}.")
        timeout = float(timeout_val)
        if timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
            raise ValueError(f"Parameter 'timeout' must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")

        # Count handling
        count_val = arguments.get("count", DEFAULT_COUNT)
        if isinstance(count_val, bool) or not isinstance(count_val, int):
            raise ValueError(f"Parameter 'count' must be an integer between 1 and {MAX_COUNT}.")
        count = int(count_val)
        if count < 1 or count > MAX_COUNT:
            raise ValueError(f"Parameter 'count' must be between 1 and {MAX_COUNT}.")

        # SSRF flag: default False
        allow_private = bool(arguments.get("allow_private", False))

        # Port handling
        port_raw = arguments.get("port")
        port = None
        if port_raw is not None:
            if isinstance(port_raw, bool) or not isinstance(port_raw, int):
                raise ValueError("Parameter 'port' must be an integer between 1 and 65535.")
            if port_raw < 1 or port_raw > 65535:
                raise ValueError(f"Parameter 'port' must be between 1 and 65535, got {port_raw}.")
            port = int(port_raw)

        server_name = arguments.get("server_name")
        if server_name is not None and (not isinstance(server_name, str) or not server_name.strip()):
            server_name = None

        verify_peer = bool(arguments.get("verify_peer", True))

        # Action dispatch
        if action == "tcp_ping":
            if port is None:
                raise ValueError("Parameter 'port' is required for action 'tcp_ping'.")
            res_data = _do_tcp_ping(host, port, timeout, count, allow_private)
            return _envelope(True, res_data)

        if action == "dns_lookup":
            raw_q = arguments.get("record_type") or arguments.get("query_type") or "ALL"
            query_type = str(raw_q).upper().strip()
            if query_type not in VALID_QUERY_TYPES:
                raise ValueError(f"Invalid query_type {query_type!r}. Supported: {sorted(VALID_QUERY_TYPES)}")
            res_data = _do_dns_lookup(host, query_type, timeout, allow_private)
            return _envelope(True, res_data)

        if action == "cert_inspect":
            target_port = port if port is not None else 443
            res_data = _do_cert_inspect(host, target_port, timeout, server_name, verify_peer, allow_private)
            return _envelope(True, res_data)

        if action == "http_head":
            use_tls_arg = arguments.get("use_tls")
            if use_tls_arg is not None:
                use_tls = bool(use_tls_arg)
                target_port = port if port is not None else (443 if use_tls else 80)
            else:
                target_port = port if port is not None else 80
                use_tls = True if target_port == 443 else False

            path = str(arguments.get("path") or "/")
            res_data = _do_http_head(
                host,
                target_port,
                path,
                use_tls,
                timeout,
                server_name,
                verify_peer,
                allow_private,
            )
            return _envelope(True, res_data)

        raise ValueError(f"Unsupported action: {action}")

    except Exception as err:
        return _envelope(False, None, error=f"{type(err).__name__}: {err}")


TOOL = {
    "name": "net_probe",
    "description": (
        "Non-destructive network diagnostic tool: probe TCP socket reachability, measure connection "
        "latency, resolve DNS records (IPv4, IPv6, PTR, CNAME), inspect TLS/SSL certificates "
        "(validity, expiration, issuer, SANs), and perform raw socket HTTP HEAD status checks "
        "with bounded timeouts and strict guardrails."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["tcp_ping", "dns_lookup", "cert_inspect", "http_head"],
                "description": "Diagnostic action to execute.",
            },
            "host": {
                "type": "string",
                "description": "Target hostname, FQDN, or IP address (e.g. 'example.com', '127.0.0.1').",
            },
            "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "description": "Target port number (1-65535). Required for 'tcp_ping', defaults to 443 for 'cert_inspect', and 80/443 for 'http_head'.",
            },
            "timeout": {
                "type": "number",
                "minimum": 0.1,
                "maximum": 10.0,
                "description": "Socket timeout in seconds (default: 5.0, maximum: 10.0).",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 0.1,
                "maximum": 10.0,
                "description": "Alias for timeout parameter.",
            },
            "count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10,
                "description": "Number of handshake probe iterations for 'tcp_ping' (default: 1, maximum: 10).",
            },
            "query_type": {
                "type": "string",
                "enum": ["A", "AAAA", "CNAME", "PTR", "ALL"],
                "description": "DNS record type to resolve for 'dns_lookup' (default: 'ALL').",
            },
            "record_type": {
                "type": "string",
                "enum": ["A", "AAAA", "CNAME", "PTR", "ALL"],
                "description": "Alias for query_type in 'dns_lookup'.",
            },
            "path": {
                "type": "string",
                "description": "HTTP request path for 'http_head' (default: '/').",
            },
            "use_tls": {
                "type": "boolean",
                "description": "Use TLS/HTTPS for 'http_head' or 'cert_inspect' (default: false for port 80, true for port 443).",
            },
            "allow_private": {
                "type": "boolean",
                "description": "Allow targeting private, loopback, or link-local IP addresses (default: false). Must be explicitly set to true to probe internal addresses.",
            },
            "server_name": {
                "type": "string",
                "description": "Optional SNI hostname override for TLS handshakes in 'cert_inspect' and 'http_head'.",
            },
            "verify_peer": {
                "type": "boolean",
                "description": "Verify TLS certificate against trust roots in 'cert_inspect' and 'http_head' (default: true).",
            },
        },
        "required": ["action", "host"],
        "additionalProperties": False,
    },
    "handler": net_probe,
    "approval": False,
}
