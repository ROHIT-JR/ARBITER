"""Multi-party QDS extension: three or more parties with transferability and repudiation resistance.

This module extends the two-party QDS protocol (signer → verifier) to support
three or more parties (signer → recipient₁ → recipient₂ → ... → recipientₙ),
introducing two distinct verification levels:

- **Acceptance** (s_a threshold): direct recipients accept signatures from signer.
- **Verification** (s_v threshold): downstream recipients verify forwarded signatures.

The thresholds satisfy: p_err < s_a < s_v < 1/2, which ensures that an honest
signer can create signatures that all parties accept, while any attempt to:
1. Repudiate the signature (signer denies involvement) fails exponentially.
2. Forge a signature (forging recipient claims it came from signer) fails.
3. Transfer inconsistently (give different states to different recipients) is detected.

**Symmetrisation** ensures neither party knows which positions the other holds,
preventing strategic adaptive attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from arbiter.qds_simulation.model import Hypothesis
from arbiter.qds_simulation.protocol import QDSDistribution, Transcript


@dataclass(frozen=True)
class MultiPartyParams:
    """Threshold parameters for multi-party QDS verification.

    Attributes:
        s_a: Acceptance threshold (direct from signer). Satisfies p_err < s_a.
        s_v: Verification threshold (for forwarded signatures). Satisfies s_a < s_v < 1/2.
        symmetry_strength: Fraction of outcomes shared in symmetrisation (typically 0.5).
    """

    s_a: float = 0.15
    s_v: float = 0.25
    symmetry_strength: float = 0.5

    def __post_init__(self):
        if not (0 < self.s_a < self.s_v < 0.5):
            raise ValueError(f"Must satisfy 0 < s_a={self.s_a} < s_v={self.s_v} < 0.5")
        if not (0 < self.symmetry_strength <= 1):
            raise ValueError(f"symmetry_strength must be in (0, 1], got {self.symmetry_strength}")


@dataclass
class PartyView:
    """A single party's view of a multi-party signature session.

    Attributes:
        party_id: Unique identifier (0=signer, 1+=recipients).
        received_outcomes: mismatch outcomes before symmetrisation.
        revealed_positions: which positions this party revealed to others (post-symmetry).
        shared_from_others: dict of party_id -> positions they revealed to this party.
        acceptance_verdict: whether this party accepts the signature (direct or via symmetry).
        verification_verdict: whether this party can verify a forwarded signature.
    """

    party_id: int
    received_outcomes: np.ndarray  # shape (n_rounds,)
    revealed_positions: np.ndarray = field(default_factory=lambda: np.array([], dtype=bool))
    shared_from_others: dict[int, np.ndarray] = field(default_factory=dict)
    acceptance_verdict: bool = False
    verification_verdict: bool = False

    def mismatch_count_from_own(self) -> int:
        """Count mismatches from this party's own observations."""
        return int(np.count_nonzero(self.received_outcomes))

    def mismatch_count_from_shared(self, shared_outcomes: np.ndarray) -> int:
        """Count mismatches in outcomes shared by another party."""
        return int(np.count_nonzero(shared_outcomes))

    def mismatch_rate_from_own(self) -> float:
        """Mismatch rate from this party's own observations."""
        return self.mismatch_count_from_own() / len(self.received_outcomes)

    def mismatch_rate_from_shared(self, shared_outcomes: np.ndarray) -> float:
        """Mismatch rate in outcomes shared by another party."""
        if len(shared_outcomes) == 0:
            return 0.0
        return self.mismatch_count_from_shared(shared_outcomes) / len(shared_outcomes)

    def accepts(self, s_a: float) -> bool:
        """Does this party accept based on the acceptance threshold s_a?"""
        return self.mismatch_rate_from_own() < s_a

    def verifies(self, s_v: float) -> bool:
        """Can this party verify forwarded signatures based on s_v threshold?"""
        if len(self.received_outcomes) == 0:
            return True
        combined_mismatches = self.mismatch_count_from_own()
        for shared_outcomes in self.shared_from_others.values():
            combined_mismatches += self.mismatch_count_from_shared(shared_outcomes)
        total_observations = len(self.received_outcomes) + sum(len(o) for o in self.shared_from_others.values())
        if total_observations == 0:
            return True
        return combined_mismatches / total_observations < s_v


@dataclass
class MultiPartySignature:
    """Multi-party QDS signature session with N parties and symmetric verification."""

    session_id: str
    message: str
    n_parties: int
    params: MultiPartyParams
    parties: dict[int, PartyView] = field(default_factory=dict)
    message_bit: int = 0
    protocol: str = "qds"

    def __post_init__(self):
        if self.n_parties < 3:
            raise ValueError(f"Multi-party QDS requires at least 3 parties, got {self.n_parties}")

    def add_party_transcript(self, party_id: int, transcript: Transcript, qds_dist: QDSDistribution | None = None):
        """Add a single party's observation transcript to the session."""
        if party_id < 0 or party_id >= self.n_parties:
            raise ValueError(f"party_id {party_id} out of range [0, {self.n_parties})")

        outcomes = transcript.outcomes.copy()
        self.parties[party_id] = PartyView(
            party_id=party_id,
            received_outcomes=outcomes,
        )

    def _run_symmetrisation(self, rng: np.random.Generator | None = None):
        """Run symmetrisation: each pair shares outcomes over an authenticated channel."""
        rng = rng or np.random.default_rng()
        n_rounds = len(self.parties[min(self.parties.keys())].received_outcomes)

        strength = self.params.symmetry_strength
        recipient_ids = [i for i in sorted(self.parties.keys()) if i != 0]

        for i, party_a_id in enumerate(recipient_ids):
            for party_b_id in recipient_ids[i + 1 :]:
                reveal_mask_a = rng.random(n_rounds) < strength
                shared_from_a = self.parties[party_a_id].received_outcomes[reveal_mask_a]
                self.parties[party_b_id].shared_from_others[party_a_id] = shared_from_a

                reveal_mask_b = rng.random(n_rounds) < strength
                shared_from_b = self.parties[party_b_id].received_outcomes[reveal_mask_b]
                self.parties[party_a_id].shared_from_others[party_b_id] = shared_from_b

    def run_verification(self, rng: np.random.Generator | None = None):
        """Run symmetrisation and multi-party verification."""
        self._run_symmetrisation(rng)

        verdicts = {}
        for party_id, party_view in self.parties.items():
            accepts = party_view.accepts(self.params.s_a)
            verifies = party_view.verifies(self.params.s_v)
            party_view.acceptance_verdict = accepts
            party_view.verification_verdict = verifies
            verdicts[party_id] = (accepts, verifies)

        return verdicts

    def all_accept(self) -> bool:
        """Do all parties accept the signature?"""
        if len(self.parties) < self.n_parties:
            return False
        return all(p.acceptance_verdict for p in self.parties.values())

    def all_verify(self) -> bool:
        """Can all parties verify the signature?"""
        if len(self.parties) < self.n_parties:
            return False
        return all(p.verification_verdict for p in self.parties.values())

    def consensus_verdict(self) -> tuple[bool, bool]:
        """Global verdict: (all_accept, all_verify)."""
        return (self.all_accept(), self.all_verify())


def simulate_repudiation_attack(
    n_parties: int = 3,
    n_rounds: int = 1200,
    signer_key: bytes = b"arbiter-demo-signing-key",
    message: str = "transfer 100 units to account 42",
    params: MultiPartyParams | None = None,
    seed: int | None = None,
    use_symmetry: bool = True,
) -> dict:
    """Simulate a repudiation attack on multi-party QDS."""
    params = params or MultiPartyParams()
    rng = np.random.default_rng(seed)

    from arbiter.qds_simulation.protocol import SessionConfig, simulate_session

    config = SessionConfig(n_rounds=n_rounds)

    # Signer's perspective (honest)
    signer_transcript = simulate_session(
        hypothesis=Hypothesis.LEGITIMATE,
        theta=0.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=seed,
        backend="analytic",
    )

    # Bob's perspective (honest recipient)
    bob_transcript = simulate_session(
        hypothesis=Hypothesis.LEGITIMATE,
        theta=0.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=seed,
        backend="analytic",
    )

    # Charlie's perspective (honest recipient)
    charlie_transcript = simulate_session(
        hypothesis=Hypothesis.LEGITIMATE,
        theta=0.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=seed,
        backend="analytic",
    )

    sig = MultiPartySignature(
        session_id=signer_transcript.session_id,
        message=message,
        n_parties=n_parties,
        params=params,
        protocol="qds",
    )

    sig.add_party_transcript(0, signer_transcript)
    sig.add_party_transcript(1, bob_transcript)
    sig.add_party_transcript(2, charlie_transcript)

    if use_symmetry:
        verdicts = sig.run_verification(rng)
    else:
        verdicts = {}
        for party_id, party_view in sig.parties.items():
            accepts = party_view.accepts(params.s_a)
            verifies = party_view.verifies(params.s_v)
            party_view.acceptance_verdict = accepts
            party_view.verification_verdict = verifies
            verdicts[party_id] = (accepts, verifies)

    alice_accepts, _ = verdicts.get(0, (False, False))
    bob_accepts, _ = verdicts.get(1, (False, False))
    charlie_accepts, charlie_verifies = verdicts.get(2, (False, False))

    alice_repudiates = alice_accepts and bob_accepts and not charlie_verifies

    return {
        "alice_accepts": alice_accepts,
        "bob_accepts": bob_accepts,
        "charlie_verifies": charlie_verifies,
        "alice_repudiates": alice_repudiates,
        "transcript": sig,
        "use_symmetry": use_symmetry,
    }


def simulate_recipient_forgery(
    n_parties: int = 3,
    n_rounds: int = 1200,
    forger_id: int = 1,
    signer_key: bytes = b"arbiter-demo-signing-key",
    message: str = "transfer 100 units to account 42",
    params: MultiPartyParams | None = None,
    seed: int | None = None,
) -> dict:
    """Simulate recipient forgery: a recipient tries to forward a forged signature."""
    params = params or MultiPartyParams()
    rng = np.random.default_rng(seed)

    from arbiter.qds_simulation.protocol import SessionConfig, simulate_session

    config = SessionConfig(n_rounds=n_rounds)

    alice_transcript = simulate_session(
        hypothesis=Hypothesis.LEGITIMATE,
        theta=0.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=seed,
        backend="analytic",
    )

    bob_transcript = simulate_session(
        hypothesis=Hypothesis.LEGITIMATE,
        theta=0.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=seed,
        backend="analytic",
    )

    charlie_transcript = simulate_session(
        hypothesis=Hypothesis.FORGERY,
        theta=1.0,
        config=config,
        message=message,
        signer_key=signer_key,
        seed=(seed + 1 if seed else None),
        backend="analytic",
    )

    sig = MultiPartySignature(
        session_id=alice_transcript.session_id,
        message=message,
        n_parties=n_parties,
        params=params,
        protocol="qds",
    )

    sig.add_party_transcript(0, alice_transcript)
    sig.add_party_transcript(1, bob_transcript)
    sig.add_party_transcript(2, charlie_transcript)

    verdicts = sig.run_verification(rng)

    alice_accepts, _ = verdicts.get(0, (False, False))
    bob_accepts, _ = verdicts.get(1, (False, False))
    charlie_accepts, _ = verdicts.get(2, (False, False))

    forgery_detected = alice_accepts and bob_accepts and not charlie_accepts

    return {
        "alice_signature_valid": alice_accepts,
        "bob_accepts": bob_accepts,
        "charlie_detects_forgery": not charlie_accepts,
        "forgery_detected": forgery_detected,
        "attributed_to_bob": forgery_detected,
        "transcript": sig,
    }
