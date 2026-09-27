import { useEffect, useState } from "react";

import { api, label, type LedgerReport, type LedgerSummary } from "../api";

export default function LedgerPanel({ version, highlight }: { version: number; highlight?: number }) {
  const [ledger, setLedger] = useState<LedgerSummary | null>(null);
  const [report, setReport] = useState<LedgerReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.ledger().then(setLedger, (e: Error) => setError(e.message));
    setReport(null);
  }, [version]);

  if (error) return <p className="error">{error}</p>;
  if (!ledger) return <p className="muted">Loading…</p>;

  return (
    <div>
      <div className="ledger-head">
        <span className="muted small mono" title={ledger.genesis_hash}>
          genesis {ledger.genesis_hash.slice(0, 20)}…
        </span>
        <button type="button" className="secondary" onClick={() => api.verifyLedger().then(setReport, (e: Error) => setError(e.message))}>
          Verify chain
        </button>
        {report && (
          <span className={`badge ${report.ok ? "ok" : "bad"}`}>
            {report.ok ? `✓ ${report.entries} entries valid` : `✗ ${report.problems[0]}`}
          </span>
        )}
      </div>
      <div className="table-wrap">
        <table className="ledger">
          <thead>
            <tr>
              <th>#</th>
              <th>time (UTC)</th>
              <th>decision</th>
              <th>attribution</th>
              <th>hash</th>
            </tr>
          </thead>
          <tbody>
            {[...ledger.entries].reverse().map((e) => (
              <tr key={e.index} className={e.index === highlight ? "hl" : ""}>
                <td>{e.index}</td>
                <td className="mono small">{e.timestamp.slice(11, 19)}</td>
                <td>{e.decision ?? <span className="muted">{e.type}</span>}</td>
                <td>{e.attribution ? label(e.attribution) : ""}</td>
                <td className="mono small" title={e.hash}>
                  {e.hash.slice(0, 12)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
