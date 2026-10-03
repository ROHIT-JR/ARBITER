"""Generate and execute notebooks/arbiter_demo.ipynb.

    python notebooks/build_demo.py

The notebook is committed with outputs so reviewers can read it on GitHub
without running anything; this script is how it is (re)built and is also run
in CI to make sure the notebook still executes.
"""

from pathlib import Path

import nbformat
from nbclient import NotebookClient

HERE = Path(__file__).parent
md, code = nbformat.v4.new_markdown_cell, nbformat.v4.new_code_cell

cells = [
    md(
        "# ARBITER walkthrough\n\n"
        "This notebook walks through the full pipeline: a teleportation-QDS session, each attack's fingerprint, "
        "the unified and sequential detectors, the information-theoretic limits, the audit ledger, trapped-ion "
        "calibration and PKI risk scoring. Every number is computed live from the `arbiter` package."
    ),
    code(
        "import numpy as np\nimport matplotlib.pyplot as plt\n\n"
        "from arbiter.qds_simulation import ATTACKS, CELLS, ChannelParams, Hypothesis, SessionConfig, "
        "cell_probabilities, expected_bell_fidelity, expected_chsh, simulate_session\n"
        "from arbiter.detection import SequentialDetector, UnifiedDetector, attack_bounds\n"
        "from arbiter.pipeline import Arbiter\n\nparams = ChannelParams()\nparams"
    ),
    md(
        "## 1. Attack fingerprints\n\n"
        "Each hypothesis induces different outcome probabilities across the observation cells: signature and "
        "freshness mismatches, four CHSH settings, and three aligned Bell-fidelity settings. The detector's "
        "likelihoods come from density matrices through the Born rule, not from tuned constants.\n\n"
        "Note how much lower the honest mismatch rate is on the aligned `bell_*` cells than on the `chsh*` "
        "cells: the +-45 degree CHSH settings maximise the Bell *violation* and pay a factor sqrt(2) in "
        "correlator magnitude, which is exactly the information the Bell-fidelity rounds recover."
    ),
    code(
        "fig, ax = plt.subplots(figsize=(9, 3.5))\nw = 0.16\n"
        "for i, h in enumerate(Hypothesis):\n"
        "    ax.bar(np.arange(len(CELLS)) + (i - 2) * w, cell_probabilities(h, 1.0, params), w, label=h.value)\n"
        "ax.set_xticks(range(len(CELLS)), CELLS, rotation=30, ha='right')\n"
        "ax.set_ylabel('P(outcome = 1)'); ax.legend(fontsize=8, ncol=5)\n"
        "ax.set_title('Per-cell outcome probabilities at full attack strength'); plt.tight_layout()\n"
        "{h.value: {'S': round(expected_chsh(h, 1.0, params), 3),\n"
        "           'F': round(expected_bell_fidelity(h, 1.0, params), 3)} for h in Hypothesis}"
    ),
    md(
        "## 2. One session on real Qiskit circuits\n\n"
        "The `qiskit` backend runs every round as an Aer circuit: Bell pair, Bell measurement, "
        "`if_test` Pauli correction and projective verification."
    ),
    code(
        "t = simulate_session(Hypothesis.REPLAY, 1.0, seed=7, backend='qiskit')\n"
        "v = Arbiter().verify(t)\nprint(v.decision, v.attribution.value)\nfor r in v.reasons: print(' -', r)\n"
        "v.unified.posterior"
    ),
    md(
        "## 3. Sequential test: raising the alarm early\n\n"
        "Under the legitimate hypothesis the log-evidence stays below log(1/α) at every round with probability "
        "at least 1-α (Ville's inequality). Under an attack it crosses within a few dozen rounds."
    ),
    code(
        "seq = SequentialDetector(params)\nfig, ax = plt.subplots(figsize=(9, 3.5))\n"
        "for h in Hypothesis:\n"
        "    r = seq.evaluate(simulate_session(h, 0.5, seed=3))\n"
        "    ax.plot(r.log_evidence[:400], label=f'{h.value} (alarm@{r.stopped_at if r.rejected else \"-\"})')\n"
        "ax.axhline(np.log(100), color='k', ls='--', lw=1, label='log(1/alpha)')\n"
        "ax.set_xlabel('round'); ax.set_ylabel('log E_t'); ax.set_ylim(-15, 40); ax.legend(fontsize=8)\n"
        "ax.set_title('Anytime-valid evidence, theta = 0.5'); plt.tight_layout()"
    ),
    md("## 4. Accuracy across attack strengths"),
    code(
        "det = UnifiedDetector(params)\nthetas = [0.05, 0.1, 0.2, 0.3, 0.5, 1.0]\nacc = {}\n"
        "for h in ATTACKS:\n"
        "    acc[h.value] = [np.mean([det.evaluate(simulate_session(h, th, seed=900 + s)).attribution is h "
        "for s in range(30)]) for th in thetas]\n"
        "fig, ax = plt.subplots(figsize=(7, 3.5))\n"
        "for k, a in acc.items(): ax.plot(thetas, a, 'o-', label=k)\n"
        "ax.set_xlabel('attack strength theta'); ax.set_ylabel('correct attribution rate'); ax.legend(fontsize=8)\n"
        "plt.tight_layout()"
    ),
    md(
        "## 5. Information-theoretic limits\n\n"
        "The quantum Chernoff exponent `xi_quantum` bounds every possible measurement. For forgery, ARBITER's "
        "projective Pauli measurement reaches it exactly.\n\n"
        "For the attacks that show up on the shared pair, `xi_quantum` is **not reachable**: it is attained by a "
        "Bell-basis measurement, which is non-local and would require the signer's and verifier's halves to be "
        "in the same place. `xi_local` is the ceiling for local measurements plus classical comparison, so "
        "`local_efficiency` is the ratio that can actually be acted on -- and the Bell-fidelity rounds are what "
        "push it toward 1."
    ),
    code(
        "import pandas as pd\npd.DataFrame(attack_bounds(1.0)).set_index('attack')"
        "[['helstrom_error_single_round', 'quantum_chernoff', 'local_chernoff', 'measured_chernoff',\n"
        "  'local_efficiency', 'measurement_efficiency']]"
        ".round(4)"
    ),
    md("## 6. Tamper-evident audit ledger"),
    code(
        "import copy\nfrom arbiter.audit_ledger import AuditLedger, LedgerKeys, verify_entries\n"
        "ledger = AuditLedger(LedgerKeys.generate(hbs_height=4))\narb = Arbiter(ledger=ledger)\n"
        "for h in (Hypothesis.LEGITIMATE, Hypothesis.FORGERY): arb.verify(simulate_session(h, seed=1))\n"
        "print('clean:', ledger.verify().ok)\nforged = copy.deepcopy(ledger.entries)\n"
        "forged[2]['payload']['decision'] = 'ACCEPT'\nprint('tampered:', verify_entries(forged).problems)"
    ),
    md("## 7. Trapped-ion calibration\n\nThe legitimate channel can be derived from ion-trap hardware figures."),
    code(
        "from arbiter.noise import PRESETS\n"
        "pd.DataFrame({k: p.visibility_budget() | {'visibility': p.visibility(), "
        "'CHSH S': 2 * np.sqrt(2) * p.visibility()} for k, p in PRESETS.items()}).round(6)"
    ),
    md("## 8. PKI quantum-risk scoring"),
    code(
        "from datetime import datetime, timedelta, timezone\nfrom arbiter.pki_risk_scoring import assess_key\n"
        "now = datetime.now(timezone.utc)\nrows = [assess_key(a, b, expires=now + timedelta(days=d)).to_dict() "
        "for a, b, d in [('RSA', 1024, 365), ('RSA', 2048, 365), ('RSA', 4096, 365 * 12), "
        "('ECDSA', 256, 90), ('Ed25519', None, 730), ('ML-DSA-65', None, 3650)]]\n"
        "pd.DataFrame(rows)[['algorithm', 'key_bits', 'shor_logical_qubits', 'mosca_violated', 'score', 'level']]"
    ),
]

nb = nbformat.v4.new_notebook(cells=cells)
nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
NotebookClient(nb, timeout=600, kernel_name="python3", resources={"metadata": {"path": str(HERE)}}).execute()
nbformat.write(nb, HERE / "arbiter_demo.ipynb")
print("wrote", HERE / "arbiter_demo.ipynb")
