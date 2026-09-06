from __future__ import annotations

import base64
import secrets
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class RealityCredentials:
    uuid: str
    private_key: str
    public_key: str
    short_id: str




def public_key_from_private(private_key: str) -> str:
    """Derive an X25519 public key from Xray/REALITY base64url private key."""
    pad = "=" * ((4 - len(private_key) % 4) % 4)
    raw = base64.urlsafe_b64decode(private_key + pad)
    if len(raw) != 32:
        raise ValueError("REALITY private key must decode to 32 bytes")
    private = X25519PrivateKey.from_private_bytes(raw)
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url(public_raw)

def generate_reality_credentials() -> RealityCredentials:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # 8 bytes -> exactly 16 lowercase hex chars, accepted by REALITY.
    short_id = secrets.token_hex(8)
    return RealityCredentials(
        uuid=str(uuid.uuid4()),
        private_key=_b64url(private_raw),
        public_key=_b64url(public_raw),
        short_id=short_id,
    )
