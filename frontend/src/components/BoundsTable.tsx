import { useEffect, useState } from "react";

import { api, label, type BoundRow } from "../api";

export default function BoundsTable() {
  const [rows, setRows] = useState<BoundRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.bounds(1).then(setRows, (e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!rows) return <p className="muted">Loading…</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>attack</th>
            <th title="quantum Chernoff exponent">ξ_Q</th>
            <th title="Chernoff exponent of ARBITER's measurements">ξ_M</th>
            <th>eff.</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.attack}>
              <td>{label(r.attack)}</td>
              <td>{r.quantum_chernoff.toFixed(3)}</td>
              <td>{r.measured_chernoff.toFixed(3)}</td>
              <td>{(r.measurement_efficiency * 100).toFixed(0)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">Full-strength attacks. Error decays as e^(−Nξ); efficiency = ξ_M / ξ_Q.</p>
    </div>
  );
}
