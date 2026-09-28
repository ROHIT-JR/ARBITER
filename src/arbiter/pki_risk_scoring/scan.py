"""Safe, opt-in TLS certificate scanning for PKI quantum-risk reports.

The scanner resolves a hostname once, rejects every non-global answer, and
connects to the selected IP address rather than asking the socket layer to
resolve the hostname again.  That closes the usual DNS-rebinding SSRF path.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass

from arbiter.pki_risk_scoring.certificates import assess_certificates
from arbiter.pki_risk_scoring.scoring import DEFAULT_CRQC_YEAR


class ScanError(ValueError):
    """A requested TLS scan could not be completed safely."""


class ScanBlockedError(ScanError):
    """A target violates the scanner's SSRF protection policy."""


@dataclass(frozen=True)
class TlsScanReport:
    host: str
    port: int
    tls_version: str | None
    cipher: str | None
    key_exchange_group: str
    certificates: list[dict]

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "key_exchange_group": self.key_exchange_group,
            "certificates": self.certificates,
        }


def parse_target(target: str, default_port: int = 443) -> tuple[str, int]:
    """Parse ``hostname[:port]`` or ``[ipv6]:port`` without accepting URLs."""
    value = target.strip()
    if not value or "://" in value or "/" in value or any(char.isspace() for char in value):
        raise ScanError("target must be a hostname, an IP address, or host:port (not a URL)")
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1:
            raise ScanError("IPv6 targets with a port must use [address]:port")
        if closing == len(value) - 1:
            host, port_text = value[1:closing], str(default_port)
        elif value[closing + 1 :].startswith(":"):
            host, port_text = value[1:closing], value[closing + 2 :]
        else:
            raise ScanError("IPv6 targets with a port must use [address]:port")
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    else:
        host, port_text = value, str(default_port)
    if not host:
        raise ScanError("target hostname is empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ScanError("target port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ScanError("target port must be between 1 and 65535")
    return host.rstrip("."), port


def resolve_public_addresses(host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve ``host`` and reject private, loopback and special-use answers."""
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanError(f"could not resolve {host!r}: {exc}") from exc
    addresses = []
    for _family, _socktype, _protocol, _canonname, sockaddr in records:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ScanBlockedError(f"refusing non-public address {address} for {host!r}")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ScanError(f"{host!r} did not resolve to a usable address")
    return addresses


def host_is_allowed(host: str, allowed_suffixes: Iterable[str]) -> bool:
    """Return whether a hostname is exactly or hierarchically allowlisted."""
    normalized = host.lower().rstrip(".")
    for suffix in allowed_suffixes:
        candidate = suffix.strip().lower().lstrip(".").rstrip(".")
        if candidate and (normalized == candidate or normalized.endswith("." + candidate)):
            return True
    return False


def _chain_der(tls_socket: ssl.SSLSocket) -> list[bytes]:
    leaf = tls_socket.getpeercert(binary_form=True)
    if not leaf:
        raise ScanError("server did not present a certificate")
    chain = [leaf]
    verified_chain = getattr(tls_socket, "get_verified_chain", None)
    if not callable(verified_chain):
        return chain
    try:
        raw_chain = verified_chain()
    except (ssl.SSLError, ValueError):
        return chain
    converted = []
    for certificate in raw_chain or []:
        if isinstance(certificate, bytes):
            converted.append(certificate)
        elif hasattr(certificate, "public_bytes"):
            raw = certificate.public_bytes()
            if isinstance(raw, bytes):
                converted.append(raw)
    return converted or chain


def scan_tls(
    host: str,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 5.0,
    *,
    protection_years_after_expiry: float = 0.0,
    crqc_year: int = DEFAULT_CRQC_YEAR,
) -> TlsScanReport:
    """Fetch and score a public TLS endpoint's certificate chain.

    TLS certificate verification is intentionally disabled because scanners
    must inspect expired and self-signed certificates too.  The report is an
    inventory signal, not a statement that the endpoint is trusted.
    """
    if not 0 < timeout <= 60:
        raise ScanError("timeout must be between 0 and 60 seconds")
    addresses = resolve_public_addresses(host, port)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((str(addresses[0]), port), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=sni or host) as tls_socket:
                certificates = _chain_der(tls_socket)
                cipher = tls_socket.cipher()
                reports = []
                for certificate in certificates:
                    reports.extend(
                        assess_certificates(
                            certificate,
                            protection_years_after_expiry=protection_years_after_expiry,
                            crqc_year=crqc_year,
                        )
                    )
                return TlsScanReport(
                    host=host,
                    port=port,
                    tls_version=tls_socket.version(),
                    cipher=cipher[0] if cipher else None,
                    key_exchange_group="unknown (not exposed by Python ssl)",
                    certificates=[report.to_dict() for report in reports],
                )
    except (OSError, ssl.SSLError) as exc:
        raise ScanError(f"TLS scan of {host}:{port} failed: {exc}") from exc
