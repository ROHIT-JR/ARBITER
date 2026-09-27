import { HYPOTHESES, label, type Verdict } from "../api";

const fmt = (x: number, d = 3) => (Number.isFinite(x) ? x.toFixed(d) : "–");

export default function VerdictPanel({ verdict }: { verdict: Verdict }) {
  const { layers: L, simulation_ground_truth: truth } = verdict;
  const reject = verdict.decision === "REJECT";
  const correct = verdict.attribution === truth.hypothesis;

  return (
    <div className="verdict">
      <div className="verdict-head">
        <span className={`badge ${reject ? "bad" : "ok"}`}>{verdict.decision}</span>
        <div>
          <div className="attribution">{label(verdict.attribution)}</div>
          <div className="muted small">
            ground truth: {label(truth.hypothesis)}
            {truth.hypothesis !== "legitimate" && ` (θ = ${truth.theta})`} · {correct ? "✓ correct" : "✗ mismatch"} ·{" "}
            {verdict.session.rounds} rounds on {verdict.session.backend}
          </div>
        </div>
      </div>

      {verdict.reasons.length > 0 && (
        <ul className="reasons">
          {verdict.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}

      <div className="two-col">
        <div>
          <h3>Attribution posterior</h3>
          {HYPOTHESES.map((h) => {
            const p = L.unified.posterior[h] ?? 0;
            return (
              <div className="bar-row" key={h}>
                <span className="bar-label">{label(h)}</span>
                <span className="bar-track">
                  <span className={`bar-fill ${h === verdict.attribution ? "hi" : ""}`} style={{ width: `${Math.max(p * 100, 0.5)}%` }} />
                </span>
                <span className="bar-value">{p < 0.001 ? "<0.001" : p.toFixed(3)}</span>
              </div>
            );
          })}
        </div>

        <table className="layers">
          <caption>Layer results</caption>
          <tbody>
            <tr>
              <th>Nonce</th>
              <td className={L.nonce_fresh ? "" : "flag"}>{L.nonce_fresh ? "fresh" : "reused"}</td>
            </tr>
            <tr>
              <th>CHSH S</th>
              <td className={L.chsh.flagged ? "flag" : ""}>
                {fmt(L.chsh.S)} ± {fmt(L.chsh.half_width, 2)} {L.chsh.certified ? "(Bell violation certified)" : ""}
              </td>
            </tr>
            <tr>
              <th>Freshness</th>
              <td className={L.freshness.flagged ? "flag" : ""}>
                {fmt(L.freshness.observed_rate)} vs {fmt(L.freshness.expected_rate)} expected (p {L.freshness.p_value < 1e-300 ? "< 1e-300" : `= ${L.freshness.p_value.toExponential(1)}`})
              </td>
            </tr>
            <tr>
              <th>Unified GLRT</th>
              <td className={L.unified.rejected ? "flag" : ""}>
                Λ = {fmt(L.unified.statistic, 2)} vs τ = {fmt(L.unified.threshold, 2)} (α = {L.unified.alpha})
              </td>
            </tr>
            <tr>
              <th>Sequential</th>
              <td className={L.sequential.rejected ? "flag" : ""}>
                {L.sequential.rejected
                  ? `alarm @ round ${L.sequential.stopped_at}, attributed @ ${L.sequential.attributed_at}`
                  : `no alarm in ${L.sequential.budget} rounds`}
              </td>
            </tr>
            {verdict.ledger && (
              <tr>
                <th>Ledger</th>
                <td className="mono">
                  #{verdict.ledger.index} · {verdict.ledger.hash.slice(0, 16)}…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
