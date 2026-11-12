"""Sign and verify a dataset with Ed25519.

The manifest holds the SHA-256 of the data file. The signature covers the manifest bytes, so a
valid signature proves that the key holder approved this exact data. The public key ships next to
the data (``signing.pub``). The private key stays on the maintainer's machine, never in the repo.

Needs the optional ``cryptography`` package (``pip install scgraph-cli[sign]``).
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

__all__ = ["SigningError", "generate_key", "sign", "verify"]


class SigningError(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:
        raise SigningError("signing needs the extra: pip install scgraph-cli[sign]") from e
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def default_key_path() -> Path:
    return Path(
        os.environ.get("SCGRAPH_SIGNING_KEY") or Path.home() / ".config/scgraph/signing.key"
    )


def generate_key(private_path: Path, public_path: Path) -> None:
    """Write a new key pair. The private file gets mode 0600. An existing key is never replaced."""
    _, ser, Priv, _ = _crypto()
    if private_path.exists():
        raise SigningError(f"{private_path} exists; refusing to replace a signing key")
    key = Priv.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    )


def _sig_path(data: Path) -> Path:
    return data.parent / f"{data.stem}.manifest.sig"


def sign(data: Path, private_path: Path) -> Path:
    """Sign the manifest of ``data``. Returns the signature file."""
    _, ser, _, _ = _crypto()
    manifest = data.parent / f"{data.stem}.manifest.json"
    if not manifest.exists():
        raise SigningError(f"{manifest} is missing; write the dataset first")
    key = ser.load_pem_private_key(private_path.read_bytes(), password=None)
    sig = key.sign(manifest.read_bytes())
    out = _sig_path(data)
    out.write_text(base64.b64encode(sig).decode() + "\n", encoding="utf-8")
    return out


def verify(data: Path, public_path: Path) -> None:
    """Raise ``SigningError`` unless the signature, the manifest and the data all agree."""
    bad, ser, _, _ = _crypto()
    manifest = data.parent / f"{data.stem}.manifest.json"
    sig = _sig_path(data)
    for p in (data, manifest, sig, public_path):
        if not p.exists():
            raise SigningError(f"{p} is missing")
    pub = ser.load_pem_public_key(public_path.read_bytes())
    try:
        pub.verify(base64.b64decode(sig.read_text().strip()), manifest.read_bytes())
    except bad as e:
        raise SigningError(f"{sig.name}: the signature does not match the manifest") from e
    import json

    want = json.loads(manifest.read_text()).get("sha256")
    if want != hashlib.sha256(data.read_bytes()).hexdigest():
        raise SigningError(f"{data.name}: the data does not match its signed manifest")
