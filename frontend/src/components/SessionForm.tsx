import { useState } from "react";

import { HYPOTHESES, label, type Hypothesis, type SessionRequest } from "../api";

interface Props {
  busy: boolean;
  onRun: (req: SessionRequest) => void;
  onResubmit?: () => void;
}

export default function SessionForm({ busy, onRun, onResubmit }: Props) {
  const [hypothesis, setHypothesis] = useState<Hypothesis>("forgery");
  const [theta, setTheta] = useState(1);
  const [rounds, setRounds] = useState(1200);
  const [backend, setBackend] = useState<"analytic" | "qiskit">("analytic");
  const [seed, setSeed] = useState("");
  const [period, setPeriod] = useState("");

  const fixedTheta = hypothesis === "legitimate" || hypothesis === "impersonation";

  return (
    <form
      className="form"
      onSubmit={(e) => {
        e.preventDefault();
        onRun({
          hypothesis,
          theta,
          n_rounds: rounds,
          backend,
          seed: seed === "" ? null : Number(seed),
          periodic_attack_every: period === "" ? null : Number(period),
        });
      }}
    >
      <label>
        Scenario
        <select value={hypothesis} onChange={(e) => setHypothesis(e.target.value as Hypothesis)}>
          {HYPOTHESES.map((h) => (
            <option key={h} value={h}>
              {label(h)}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>
          Attack strength θ <output>{fixedTheta ? (hypothesis === "impersonation" ? "1 (all-or-nothing)" : "–") : theta.toFixed(2)}</output>
        </span>
        <input
          type="range"
          min={0.05}
          max={1}
          step={0.05}
          value={theta}
          disabled={fixedTheta}
          onChange={(e) => setTheta(Number(e.target.value))}
        />
      </label>
      <label>
        Rounds
        <input type="number" min={100} max={20000} step={100} value={rounds} onChange={(e) => setRounds(Number(e.target.value))} />
      </label>
      <label>
        Backend
        <select value={backend} onChange={(e) => setBackend(e.target.value as "analytic" | "qiskit")}>
          <option value="analytic">analytic (density matrices)</option>
          <option value="qiskit">qiskit (Aer circuits)</option>
        </select>
      </label>
      <label>
        <span>
          Seed <span className="muted">(optional)</span>
        </span>
        <input type="number" value={seed} placeholder="random" onChange={(e) => setSeed(e.target.value)} />
      </label>
      <label>
        <span>
          Periodic attack every <span className="muted">(optional demo fixture)</span>
        </span>
        <input
          type="number"
          min={1}
          step={1}
          value={period}
          placeholder="k rounds"
          disabled={fixedTheta}
          onChange={(e) => setPeriod(e.target.value)}
        />
      </label>
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Running…" : "Run session"}
        </button>
        <button type="button" className="secondary" disabled={busy || !onResubmit} onClick={onResubmit}
          title="Submit the last transcript again verbatim (classical replay)">
          Resubmit last
        </button>
      </div>
    </form>
  );
}
