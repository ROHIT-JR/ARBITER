import socket
import ssl
import threading

import pytest

from arbiter.cli import main
from arbiter.pki_risk_scoring.scan import (
    ScanBlockedError,
    host_is_allowed,
    parse_target,
    resolve_public_addresses,
    scan_tls,
)


def _local_tls_server(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from test_pki import _self_signed

    key = rsa.generate_private_key(65537, 2048)
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(_self_signed(key, 30))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        try:
            connection, _ = listener.accept()
            with context.wrap_socket(connection, server_side=True):
                pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def test_scan_tls_fetches_and_scores_a_local_server_after_safe_resolution(tmp_path, monkeypatch):
    import arbiter.pki_risk_scoring.scan as scan_module

    port, thread = _local_tls_server(tmp_path)

    def redirect_connection(_address, timeout=None, source_address=None):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout is not None:
            connection.settimeout(timeout)
        if source_address:
            connection.bind(source_address)
        connection.connect(("127.0.0.1", port))
        return connection

    monkeypatch.setattr(
        scan_module.socket,
        "getaddrinfo",
        lambda _host, requested_port, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", requested_port))
        ],
    )
    monkeypatch.setattr(
        scan_module.socket,
        "create_connection",
        redirect_connection,
    )

    report = scan_tls("public.example", port, timeout=2)
    thread.join(timeout=2)
    assert report.host == "public.example"
    assert report.tls_version and report.cipher
    assert report.key_exchange_group.startswith("unknown")
    assert len(report.certificates) == 1
    assert report.certificates[0]["public_key"]["algorithm"] == "RSA"


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.8", "169.254.169.254", "::1", "fc00::1"])
def test_non_public_dns_answers_are_blocked(address, monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, port),
            )
        ],
    )
    with pytest.raises(ScanBlockedError, match="non-public"):
        resolve_public_addresses("blocked.example", 443)


def test_target_and_allowlist_parsing():
    assert parse_target("example.com:8443") == ("example.com", 8443)
    assert parse_target("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert parse_target("[2001:db8::1]") == ("2001:db8::1", 443)
    assert host_is_allowed("api.example.com", ["example.com"])
    assert host_is_allowed("example.com", [".example.com"])
    assert not host_is_allowed("notexample.com", ["example.com"])
    with pytest.raises(ValueError):
        parse_target("https://example.com")


def test_cli_refuses_private_targets(capsys):
    assert main(["pki", "scan", "127.0.0.1"]) == 2
    assert "non-public" in capsys.readouterr().err
