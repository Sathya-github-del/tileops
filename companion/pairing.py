"""First-start state: API bearer token, random ntfy topic, pairing QR."""
from __future__ import annotations

import os
import secrets
import string
from pathlib import Path
from urllib.parse import quote

from .config import Config

ALPHABET = string.ascii_letters + string.digits


def _write_secret(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    path.chmod(0o600)


def ensure_state(cfg: Config) -> tuple[str, bool]:
    """Create state dir, API token and ntfy topic if missing. Returns (token, first_start)."""
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    cfg.state_dir.chmod(0o700)
    tok_path = cfg.state_dir / "api_token"
    first = not tok_path.exists()
    if first:
        _write_secret(tok_path, secrets.token_urlsafe(32))
    token = tok_path.read_text().strip()

    topic_path = cfg.state_dir / "ntfy_topic"
    if not cfg.ntfy_topic:
        if not topic_path.exists():
            _write_secret(topic_path, "".join(secrets.choice(ALPHABET) for _ in range(32)))
        cfg.ntfy_topic = topic_path.read_text().strip()
    return token, first


def cert_fingerprints(cfg: Config) -> tuple[str, str] | None:
    """(pin for the app, human colon-hex) if the companion serves HTTPS."""
    crt = cfg.state_dir / "tls.crt"
    if not cfg.tls or not crt.exists():
        return None
    from .tls import fingerprint, fingerprint_human
    return fingerprint(crt), fingerprint_human(crt)


def pair_uri(cfg: Config, token: str) -> str:
    uri = f"tileops://pair?url={quote(cfg.public_url, safe='')}&token={quote(token, safe='')}"
    fps = cert_fingerprints(cfg)
    return uri + (f"&fp={fps[0]}" if fps else "")


def print_pairing(cfg: Config, token: str, save_png: bool = True) -> str:
    import qrcode

    uri = pair_uri(cfg, token)
    qr = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    print("=" * 64)
    print("TileOps companion is running. Connect the TileOps app with ONE of these:")
    print()
    print("  1) Scan the QR code below with the app (Connect -> Scan QR code)")
    print("  2) Or copy this pairing link and paste it in the app (Connect -> Paste pairing link):")
    print(f"     {uri}")
    print("  3) Or type it in by hand (Connect -> Enter it myself):")
    print(f"     Address:      {cfg.public_url}")
    print(f"     Pairing code: {token}")
    fps = cert_fingerprints(cfg)
    if fps:
        print(f"     Certificate:  SHA-256 {fps[1]}")
        print("     (the app shows this when you enter it by hand: check that they match)")
    print()
    print(f"  Alerts also go to ntfy topic: {cfg.ntfy_topic}  (subscribe to it in the ntfy app)")
    print("  Keep the pairing code private: it gives full access to this companion.")
    print("  Show this again any time: python -m companion pair")
    print()
    qr.print_ascii(invert=True)
    png = cfg.state_dir / "pair.png"
    if save_png:
        try:
            from qrcode.image.pure import PyPNGImage

            img = qrcode.make(uri, image_factory=PyPNGImage, box_size=8, border=2)
            with open(png, "wb") as f:
                img.save(f)
            png.chmod(0o600)
            print(f"QR saved to {png}")
        except Exception as e:  # noqa: BLE001
            print(f"(could not save pair.png: {e})")
    print("=" * 64, flush=True)
    return uri
