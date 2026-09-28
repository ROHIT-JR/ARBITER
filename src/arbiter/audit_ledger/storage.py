"""Encrypted key storage for audit ledger.

Uses AES-256-GCM with Argon2id key derivation for at-rest encryption.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

STORAGE_VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass
class EncryptedKeys:
    version: int
    salt: str  # base64
    nonce: str  # base64
    ciphertext: str  # base64

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, data: str) -> EncryptedKeys:
        d = json.loads(data)
        return cls(**d)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=3,
        lanes=4,
        memory_cost=65536,
    )
    return kdf.derive(passphrase.encode())


def encrypt_keys(
    plaintext: bytes,
    passphrase: str,
) -> EncryptedKeys:
    """Encrypt key material with a passphrase."""
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return EncryptedKeys(
        version=STORAGE_VERSION,
        salt=base64.b64encode(salt).decode(),
        nonce=base64.b64encode(nonce).decode(),
        ciphertext=base64.b64encode(ciphertext).decode(),
    )


def decrypt_keys(
    encrypted: EncryptedKeys,
    passphrase: str,
) -> bytes:
    """Decrypt key material with a passphrase."""
    if encrypted.version != STORAGE_VERSION:
        raise ValueError(f"unsupported storage version: {encrypted.version}")
    salt = base64.b64decode(encrypted.salt)
    nonce = base64.b64decode(encrypted.nonce)
    ciphertext = base64.b64decode(encrypted.ciphertext)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


class EncryptedKeyStore:
    """Encrypted on-disk key storage for LedgerKeys."""

    def __init__(self, path: Path):
        self.path = path

    def save(self, keys_data: dict, passphrase: str) -> None:
        """Save encrypted keys to disk."""
        plaintext = json.dumps(keys_data).encode()
        encrypted = encrypt_keys(plaintext, passphrase)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(encrypted.to_json())

    def load(self, passphrase: str) -> dict:
        """Load and decrypt keys from disk."""
        encrypted = EncryptedKeys.from_json(self.path.read_text())
        plaintext = decrypt_keys(encrypted, passphrase)
        return json.loads(plaintext)

    def exists(self) -> bool:
        return self.path.exists()
