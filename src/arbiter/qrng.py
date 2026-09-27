"""Hadamard-measurement QRNG.

On a simulator this is only as random as the simulator's seed -- it is a
faithful *model* of a QRNG (ITU-T X.1702-style source: prepare |+>, measure
in Z), and becomes a genuine entropy source only when pointed at hardware.
Pass ``seed`` for reproducible experiments.
"""

from __future__ import annotations

import secrets

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

_CIRCUIT = QuantumCircuit(1, 1)
_CIRCUIT.h(0)
_CIRCUIT.measure(0, 0)


class QRNG:
    def __init__(self, seed: int | None = None):
        self._seed = secrets.randbits(31) if seed is None else seed
        self._calls = 0
        self._sim = AerSimulator()

    def bits(self, n: int) -> list[int]:
        self._calls += 1
        result = self._sim.run(
            _CIRCUIT, shots=n, memory=True, seed_simulator=self._seed + 7919 * self._calls
        ).result()
        return [int(b) for b in result.get_memory()]

    def token_bytes(self, n: int) -> bytes:
        bits = self.bits(8 * n)
        return bytes(int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, 8 * n, 8))

    def seed_int(self) -> int:
        """64 bits of QRNG output, for seeding bulk classical sampling."""
        return int.from_bytes(self.token_bytes(8), "big")
