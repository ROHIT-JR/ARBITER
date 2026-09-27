"""The two independent post-quantum signatures on every ledger entry.

* **ML-DSA-65** (FIPS 204, lattice-based) via liboqs when installed, else the
  pure-Python ``dilithium-py`` implementation.
* **Merkle-Lamport** -- a stateful hash-based signature in the XMSS/LMS
  family (NIST SP 800-208): 2^h Lamport one-time keys under a Merkle root.
  Its security rests only on SHA3/SHAKE, so it is independent of the lattice
  assumption behind ML-DSA. Lamport's scheme is also the classical skeleton
  that Gottesman-Chuang quantum digital signatures quantise.

An entry is accepted only if *both* verify, so forging the ledger requires
breaking both assumptions.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

_N = 32          # hash output bytes
_BITS = 256      # signed digest bits


def _h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


# --- ML-DSA ---------------------------------------------------------------

class MLDSA:
    """ML-DSA-65 keypair with a backend-agnostic interface."""

    ALGORITHM = "ML-DSA-65"

    def __init__(self, public_key: bytes | None = None, secret_key: bytes | None = None):
        self.backend = _mldsa_backend()
        if public_key is None:
            public_key, secret_key = self.backend.keygen()
        self.public_key = public_key
        self.secret_key = secret_key

    def sign(self, message: bytes) -> bytes:
        return self.backend.sign(self.secret_key, message)

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return bool(_mldsa_backend().verify(public_key, message, signature))
        except Exception:
            return False


class _DilithiumPy:
    name = "dilithium-py"

    def __init__(self):
        from dilithium_py.ml_dsa import ML_DSA_65

        self._impl = ML_DSA_65

    def keygen(self):
        return self._impl.keygen()

    def sign(self, sk, msg):
        return self._impl.sign(sk, msg)

    def verify(self, pk, msg, sig):
        return self._impl.verify(pk, msg, sig)


class _LibOQS:
    name = "liboqs"

    def __init__(self):
        import oqs  # noqa: F401

        self._oqs = oqs

    def keygen(self):
        with self._oqs.Signature(MLDSA.ALGORITHM) as s:
            pk = s.generate_keypair()
            return pk, s.export_secret_key()

    def sign(self, sk, msg):
        with self._oqs.Signature(MLDSA.ALGORITHM, sk) as s:
            return s.sign(msg)

    def verify(self, pk, msg, sig):
        with self._oqs.Signature(MLDSA.ALGORITHM) as s:
            return s.verify(msg, sig, pk)


_BACKEND = None


def _mldsa_backend():
    global _BACKEND
    if _BACKEND is None:
        try:
            _BACKEND = _LibOQS()
        except Exception:
            _BACKEND = _DilithiumPy()
    return _BACKEND


# --- Merkle-Lamport -------------------------------------------------------

@dataclass
class HashSignature:
    leaf: int
    reveal: list[bytes]       # sk[j][bit_j] for each digest bit j
    counterpart: list[bytes]  # pk[j][1 - bit_j], so the verifier can rebuild the leaf
    auth_path: list[bytes]

    def to_dict(self) -> dict:
        return {
            "leaf": self.leaf,
            "reveal": _b64(b"".join(self.reveal)),
            "counterpart": _b64(b"".join(self.counterpart)),
            "auth_path": [a.hex() for a in self.auth_path],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HashSignature":
        return cls(d["leaf"], _chunks(_unb64(d["reveal"])), _chunks(_unb64(d["counterpart"])),
                   [bytes.fromhex(a) for a in d["auth_path"]])


def _chunks(b: bytes) -> list[bytes]:
    return [b[i : i + _N] for i in range(0, len(b), _N)]


def _digest_bits(message: bytes) -> list[int]:
    d = _h(message)
    return [(d[j // 8] >> (7 - j % 8)) & 1 for j in range(_BITS)]


class MerkleLamport:
    """2**height one-time Lamport keys, all derived from ``seed``."""

    def __init__(self, seed: bytes, height: int = 8):
        self.seed = seed
        self.height = height
        leaves = [self._leaf_hash(i) for i in range(2**height)]
        self._levels = [leaves]
        while len(self._levels[-1]) > 1:
            prev = self._levels[-1]
            self._levels.append([_h(prev[i] + prev[i + 1]) for i in range(0, len(prev), 2)])

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    @property
    def capacity(self) -> int:
        return 2**self.height

    def _sk(self, leaf: int, j: int, b: int) -> bytes:
        return hashlib.shake_256(self.seed + leaf.to_bytes(4, "big") + j.to_bytes(2, "big") + bytes([b])).digest(_N)

    def _leaf_hash(self, leaf: int) -> bytes:
        return _h(b"".join(_h(self._sk(leaf, j, b)) for j in range(_BITS) for b in (0, 1)))

    def sign(self, message: bytes, leaf: int) -> HashSignature:
        if not 0 <= leaf < self.capacity:
            raise ValueError("hash-based key exhausted")
        bits = _digest_bits(message)
        reveal = [self._sk(leaf, j, bits[j]) for j in range(_BITS)]
        counterpart = [_h(self._sk(leaf, j, 1 - bits[j])) for j in range(_BITS)]
        path, idx = [], leaf
        for level in self._levels[:-1]:
            path.append(level[idx ^ 1])
            idx //= 2
        return HashSignature(leaf, reveal, counterpart, path)

    @staticmethod
    def verify(root: bytes, message: bytes, sig: HashSignature) -> bool:
        if len(sig.reveal) != _BITS or len(sig.counterpart) != _BITS:
            return False
        bits = _digest_bits(message)
        parts = []
        for j in range(_BITS):
            mine, other = _h(sig.reveal[j]), sig.counterpart[j]
            parts.extend((mine, other) if bits[j] == 0 else (other, mine))
        node, idx = _h(b"".join(parts)), sig.leaf
        for sibling in sig.auth_path:
            node = _h(node + sibling) if idx % 2 == 0 else _h(sibling + node)
            idx //= 2
        return node == root
