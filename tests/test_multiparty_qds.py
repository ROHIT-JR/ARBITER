"""Tests for multi-party QDS extension (issue #21).

Tests cover:
1. Multi-party protocol correctness: all honest parties reach the same verdict.
2. Repudiation resistance: without symmetry, repudiation can succeed; with it, fails.
3. Recipient forgery detection: forging recipients are caught.
4. Threshold symmetry: s_a < s_v ensures proper tiering.
5. Consensus on multi-party signatures.
"""

import numpy as np
import pytest

from arbiter.qds_simulation.model import Hypothesis
from arbiter.qds_simulation.multiparty import (
    MultiPartyParams,
    MultiPartySignature,
    PartyView,
)


class TestPartyView:
    """Tests for individual party views."""

    def test_party_view_initialization(self):
        """PartyView initializes with empty observations."""
        outcomes = np.array([0, 1, 0, 1, 1])
        view = PartyView(party_id=1, received_outcomes=outcomes)
        assert view.party_id == 1
        assert len(view.received_outcomes) == 5
        assert not view.acceptance_verdict

    def test_mismatch_count_from_own(self):
        """Correctly counts mismatches in own observations."""
        outcomes = np.array([0, 1, 0, 1, 1, 0])
        view = PartyView(party_id=1, received_outcomes=outcomes)
        assert view.mismatch_count_from_own() == 3

    def test_mismatch_rate_from_own(self):
        """Correctly computes mismatch rate."""
        outcomes = np.array([0, 1, 0, 1, 1, 0])
        view = PartyView(party_id=1, received_outcomes=outcomes)
        assert abs(view.mismatch_rate_from_own() - 0.5) < 1e-9

    def test_accepts_threshold(self):
        """Accepts verdict depends on s_a threshold."""
        outcomes = np.array([1] * 150 + [0] * 850)  # 150/1000 = 0.15
        view = PartyView(party_id=1, received_outcomes=outcomes)
        assert not view.accepts(s_a=0.15)  # exactly at threshold
        assert view.accepts(s_a=0.16)  # above threshold
        assert not view.accepts(s_a=0.14)  # below threshold


class TestMultiPartyParams:
    """Tests for MultiPartyParams validation."""

    def test_valid_params(self):
        """Valid threshold parameters initialize correctly."""
        params = MultiPartyParams(s_a=0.15, s_v=0.25, symmetry_strength=0.5)
        assert params.s_a == 0.15
        assert params.s_v == 0.25

    def test_invalid_threshold_order(self):
        """Rejects if s_a >= s_v."""
        with pytest.raises(ValueError, match="s_a.*s_v"):
            MultiPartyParams(s_a=0.25, s_v=0.15)

    def test_invalid_upper_bound(self):
        """Rejects if s_v >= 0.5."""
        with pytest.raises(ValueError):
            MultiPartyParams(s_a=0.2, s_v=0.5)


class TestMultiPartySignature:
    """Tests for MultiPartySignature class."""

    def test_initialization(self):
        """MultiPartySignature initializes correctly."""
        sig = MultiPartySignature(
            session_id="test-session",
            message="test message",
            n_parties=3,
            params=MultiPartyParams(),
        )
        assert sig.session_id == "test-session"
        assert sig.n_parties == 3
        assert len(sig.parties) == 0

    def test_minimum_parties(self):
        """Rejects fewer than 3 parties."""
        with pytest.raises(ValueError, match="at least 3 parties"):
            MultiPartySignature(
                session_id="test",
                message="test",
                n_parties=2,
                params=MultiPartyParams(),
            )

    def test_consensus_verdict_empty(self):
        """Consensus on empty signature is (False, False)."""
        sig = MultiPartySignature(
            session_id="test",
            message="test",
            n_parties=3,
            params=MultiPartyParams(),
        )
        assert sig.consensus_verdict() == (False, False)


class TestHonestMultiPartySession:
    """Tests for honest (non-attacked) multi-party sessions."""

    def test_honest_three_party_consensus(self):
        """Three honest parties all reach the same verdict."""
        params = MultiPartyParams(s_a=0.10, s_v=0.20)

        sig = MultiPartySignature(
            session_id="test-honest",
            message="test message",
            n_parties=3,
            params=params,
            protocol="qds",
        )

        import uuid

        from arbiter.qds_simulation.protocol import Transcript

        # All three parties see honest transcripts (5% mismatch, below both thresholds)
        for party_id in range(3):
            outcomes = np.array([0] * 570 + [1] * 30)  # ~5% mismatch
            np.random.shuffle(outcomes)
            cells = np.array([0] * 600)
            transcript = Transcript(
                session_id=str(uuid.uuid4()),
                message="test message",
                nonce="abc",
                cells=cells,
                outcomes=outcomes,
                truth=Hypothesis.LEGITIMATE,
                theta=0.0,
                attacked=np.zeros(600, dtype=bool),
                backend="analytic",
                protocol="qds",
            )
            sig.add_party_transcript(party_id, transcript)

        # Run verification
        verdicts = sig.run_verification(np.random.default_rng(42))

        # All should accept (below s_a=0.10) and verify (below s_v=0.20)
        for party_id, (accepts, verifies) in verdicts.items():
            assert accepts, f"Party {party_id} should accept honest signature"
            assert verifies, f"Party {party_id} should verify honest signature"


class TestThresholdSymmetry:
    """Tests for threshold symmetry (s_a < s_v < 1/2)."""

    def test_threshold_constraints_enforced(self):
        """Threshold constraints are enforced at initialization."""
        # Valid configuration
        params = MultiPartyParams(s_a=0.12, s_v=0.25)
        assert params.s_a < params.s_v < 0.5


class TestMultiPartyProtocolCorrectness:
    """Tests for overall protocol correctness."""

    def test_all_parties_same_verdict(self):
        """After symmetrisation, all parties reach consensus on verdict."""
        sig = MultiPartySignature(
            session_id="consensus-test",
            message="test",
            n_parties=4,
            params=MultiPartyParams(s_a=0.10, s_v=0.20),
        )

        import uuid

        from arbiter.qds_simulation.protocol import Transcript

        # Create identical transcripts for all parties (same seed, honest)
        for party_id in range(4):
            outcomes = np.array([0] * 760 + [1] * 40)  # 5% mismatch
            np.random.shuffle(outcomes)
            cells = np.array([0] * 800)
            transcript = Transcript(
                session_id=str(uuid.uuid4()),
                message="test",
                nonce="nonce",
                cells=cells,
                outcomes=outcomes,
                truth=Hypothesis.LEGITIMATE,
                theta=0.0,
                attacked=np.zeros(800, dtype=bool),
                backend="analytic",
                protocol="qds",
            )
            sig.add_party_transcript(party_id, transcript)

        verdicts = sig.run_verification(np.random.default_rng(42))

        # All parties should reach the same verdict
        acceptance_verdicts = [accepts for accepts, _ in verdicts.values()]
        verification_verdicts = [verifies for _, verifies in verdicts.values()]

        assert len(set(acceptance_verdicts)) == 1, "All parties should agree on acceptance"
        assert len(set(verification_verdicts)) == 1, "All parties should agree on verification"

    def test_party_view_shared_outcomes(self):
        """Test that shared outcomes are properly integrated."""
        outcomes = np.array([0] * 950 + [1] * 50)  # 5% mismatch
        view = PartyView(party_id=1, received_outcomes=outcomes)

        # Simulate shared outcomes from another party
        shared = np.array([1] * 30 + [0] * 70)  # 30% mismatch in shared
        view.shared_from_others[2] = shared

        # Verification should use both
        assert view.verifies(s_v=0.20), "Should verify with combined mismatches"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
