"""Self-signed TLS for the companion, pinned by the app.

The companion has no domain name and its LAN IP can change, so a CA-issued certificate isn't
practical. Instead it makes its own certificate on first start; the SHA-256 fingerprint of that
certificate travels in the pairing QR/link, and the app trusts exactly that certificate."""
from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure_cert(state_dir: Path, host: str) -> tuple[Path, Path]:
    key_p, crt_p = state_dir / "tls.key", state_dir / "tls.crt"
    if key_p.exists() and crt_p.exists():
        return key_p, crt_p
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TileOps companion")])
    sans: list[x509.GeneralName] = [x509.DNSName("tileops-companion")]
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        if host:
            sans.append(x509.DNSName(host))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    fd = os.open(key_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    crt_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_p, crt_p


def fingerprint(crt_path: Path) -> str:
    """base64url(SHA-256(DER)), no padding: what the app pins (fp= in the pairing link)."""
    der = x509.load_pem_x509_certificate(crt_path.read_bytes()).public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")


def fingerprint_human(crt_path: Path) -> str:
    """Same fingerprint in the familiar colon-hex form, for comparing by eye."""
    der = x509.load_pem_x509_certificate(crt_path.read_bytes()).public_bytes(serialization.Encoding.DER)
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
