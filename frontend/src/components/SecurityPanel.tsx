import { useEffect, useState } from "react";

import { api, type ProtocolSecurityResponse } from "../api";

const scientific = (value: number) => value.toExponential(1);

export default function SecurityPanel() {
  const [report, setReport] = useState<ProtocolSecurityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.security().then(setReport, (reason: Error) => setError(reason.message));
  }, []);

  if (error) return <p className="error">Security bounds unavailable: {error}</p>;
  if (!report) return <p className="muted">Calculating finite-size protocol bounds…</p>;

  return (
    <div>
      <div className="security-head">
        <div>
          <h2>QDS protocol security</h2>
          <p className="muted small">Finite-size Hoeffding bounds for the BB84 state-elimination signature protocol.</p>
        </div>
        <span className="metric-chip">ε ≤ {scientific(report.bounds.epsilon)}</span>
      </div>
      <div className="security-summary">
        <strong>{report.minimum_length.toLocaleString()} key elements</strong>
        <span className="muted small">required at visibility {report.visibility.toFixed(3)} for target ε = {scientific(report.target_epsilon)}</span>
      </div>
      <div className="table-wrap">
        <table>
          <caption>Maximum protocol failure bound by signature length</caption>
          <thead><tr><th>L</th><th>max ε</th><th>forge</th><th>repudiate</th><th>honest abort</th></tr></thead>
          <tbody>
            {report.curve.map((point) => (
              <tr key={point.length} className={point.length === report.minimum_length ? "hl" : ""}>
                <td>{point.length.toLocaleString()}</td>
                <td>{scientific(point.epsilon)}</td>
                <td>{scientific(point.p_forge)}</td>
                <td>{scientific(point.p_rep)}</td>
                <td>{scientific(point.p_rob)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Assumes collective attacks, independent elements, and ideal analytical symmetrisation; not a composable proof.</p>
    </div>
  );
}
