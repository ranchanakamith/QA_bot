"""HTTPS path: a self-signed certificate must be reported, and the scan must still complete."""
import datetime as dt
import ssl
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from demo_site.server import make_server  # noqa: E402
from qabot.config import load_config  # noqa: E402
from qabot.scan import run_scan  # noqa: E402


def self_signed(folder: Path) -> tuple:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=5)).sign(key, hashes.SHA256()))
    cert_file, key_file = folder / "cert.pem", folder / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return cert_file, key_file


def test_self_signed_https_site(tmp_path):
    cert_file, key_file = self_signed(tmp_path)
    server = make_server(port=0, good=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = load_config(overrides={
            "crawl": {"check_external": False, "requests_per_second": 50},
            "security": {"local_targets_skip_transport": False}})     # treat 127.0.0.1 like a public site
        report = run_scan(f"https://127.0.0.1:{server.server_address[1]}", cfg, log=lambda *_: None)
    finally:
        server.shutdown()
        server.server_close()

    rules = {f["rule"] for f in report["findings"]}
    assert report["smoke"]["passed"]
    assert "tls-cert-invalid" in rules                 # high finding
    assert "missing-hsts" in rules
    assert "tls-cert-expiring" not in rules            # not reported on top of an invalid certificate
    assert "no-https" not in rules
    assert report["score"]["score"] <= 74 and report["score"]["gates"][0]["id"] == "security_high"
    assert report["check_details"]["tls_headers"]["tls"]["protocol"] in ("TLSv1.2", "TLSv1.3")
    assert len(report["pages"]) >= 4                   # the crawl carried on despite the certificate
    if report["browser"]:
        assert report["check_details"]["page_speed"]["mode"] == "browser"
