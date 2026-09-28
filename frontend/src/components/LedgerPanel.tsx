import { useEffect, useState } from "react";

import { api, label, type LedgerReport, type LedgerSummary } from "../api";

export default function LedgerPanel({ version, highlight, demoMode }: { version: number; highlight?: number; demoMode: boolean }) {
  const [ledger, setLedger] = useState<LedgerSummary | null>(null);
  const [report, setReport] = useState<LedgerReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => api.ledger().then(setLedger, (e: Error) => setError(e.message));

  useEffect(() => {
    refresh();
    setReport(null);
  }, [version]);

  const tamper = async (index: number, value: string, recomputeHashes: boolean) => {
    setError(null);
    try {
      setReport(await api.tamperLedger(index, "decision", value, recomputeHashes));
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const restore = async () => {
    setError(null);
    try {
      setReport(await api.restoreLedger());
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

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
      {demoMode && <p className="demo-note">Demo mode: tamper actions affect memory only and never the saved ledger.</p>}
      {report && !report.ok && (
        <div className="tamper-report" role="alert">
          <span>Tamper detected at entry {report.first_bad_index}: {report.problems[0]}</span>
          {demoMode && <button type="button" className="secondary" onClick={restore}>Restore saved ledger</button>}
        </div>
      )}
      <div className="table-wrap">
        <table className="ledger">
          <thead>
            <tr>
              <th>#</th>
              <th>time (UTC)</th>
              <th>decision</th>
              <th>attribution</th>
              <th>hash</th>
              {demoMode && <th>demo</th>}
            </tr>
          </thead>
          <tbody>
            {[...ledger.entries].reverse().map((e) => {
              const isTampered = report?.ok === false && report.first_bad_index === e.index;
              const nextDecision = e.decision === "ACCEPT" ? "REJECT" : "ACCEPT";
              return (
              <tr key={e.index} className={`${e.index === highlight ? "hl" : ""} ${isTampered ? "tampered" : ""}`}>
                <td>{e.index}</td>
                <td className="mono small">{e.timestamp.slice(11, 19)}</td>
                <td>{e.decision ?? <span className="muted">{e.type}</span>}</td>
                <td>{e.attribution ? label(e.attribution) : ""}</td>
                <td className="mono small" title={e.hash}>
                  {e.hash.slice(0, 12)}…
                </td>
                {demoMode && (
                  <td>
                    {e.decision ? (
                      <div className="ledger-actions">
                        <button type="button" className="secondary danger" onClick={() => tamper(e.index, nextDecision, false)}>
                          Tamper
                        </button>
                        <button type="button" className="secondary danger" onClick={() => tamper(e.index, nextDecision, true)}>
                          Tamper + rehash
                        </button>
                      </div>
                    ) : <span className="muted small">—</span>}
                  </td>
                )}
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
