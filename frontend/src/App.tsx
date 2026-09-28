import { useCallback, useEffect, useState } from "react";

import { api, type DemoAccuracyCache, type DemoScenario, type SessionRequest, type Verdict } from "./api";
import AccuracyPanel from "./components/AccuracyPanel";
import BoundsTable from "./components/BoundsTable";
import DemoMenu from "./components/DemoMenu";
import EvidenceChart from "./components/EvidenceChart";
import LedgerPanel from "./components/LedgerPanel";
import SessionForm from "./components/SessionForm";
import VerdictPanel from "./components/VerdictPanel";

export default function App() {
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
  );
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [ledgerVersion, setLedgerVersion] = useState(0);
  const [demoResults, setDemoResults] = useState<Record<string, Verdict>>({});
  const [demoCache, setDemoCache] = useState<DemoAccuracyCache | null>(null);
  const [tamperReport, setTamperReport] = useState<Awaited<ReturnType<typeof api.tamperLedger>> | null>(null);

  const checkHealth = useCallback(() => {
    api.health().then(
      (health) => {
        setOnline(true);
        setDemoMode(health.demo_mode);
      },
      () => {
        setOnline(false);
        setDemoMode(false);
      },
    );
  }, []);

  useEffect(() => {
    checkHealth();
    const id = window.setInterval(checkHealth, 10_000);
    return () => window.clearInterval(id);
  }, [checkHealth]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const run = useCallback(async (action: () => Promise<Verdict>) => {
    setBusy(true);
    setError(null);
    setTamperReport(null);
    try {
      const nextVerdict = await action();
      setVerdict(nextVerdict);
      setLedgerVersion((v) => v + 1);
      return nextVerdict;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      checkHealth();
      return null;
    } finally {
      setBusy(false);
    }
  }, [checkHealth]);

  const onRun = (req: SessionRequest) => run(() => api.runSession({ ...req, trajectory: true }));
  const onResubmit = verdict ? () => run(() => api.resubmit(verdict.session.id)) : undefined;

  const onDemoScenario = useCallback(async (scenario: DemoScenario) => {
    if (scenario.kind === "accuracy" && scenario.cached_result) {
      setDemoCache(scenario.cached_result);
      document.getElementById("accuracy-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    if (scenario.kind === "hardware") {
      setError("This build has no cached hardware result; the offline demo intentionally skips it.");
      return;
    }
    if (scenario.kind === "session" && scenario.request) {
      const result = await onRun(scenario.request as SessionRequest);
      if (result) setDemoResults((current) => ({ ...current, [scenario.id]: result }));
      return;
    }
    const source = scenario.source ? demoResults[scenario.source] : undefined;
    if (!source) {
      setError(`Run the ${scenario.source} preset first so this follow-up has a deterministic source transcript.`);
      return;
    }
    if (scenario.kind === "resubmit") {
      const result = await run(() => api.resubmit(source.session.id));
      if (result) setDemoResults((current) => ({ ...current, [scenario.id]: result }));
      return;
    }
    if (scenario.kind === "tamper" && scenario.request) {
      try {
        const request = scenario.request as { field: "decision" | "attribution" | "timestamp"; value: string; recompute_hashes: boolean };
        const report = await api.tamperLedger(source.ledger!.index, request.field, request.value, request.recompute_hashes);
        setTamperReport(report);
        setLedgerVersion((version) => version + 1);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    }
  }, [demoResults, onRun, run]);

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>ARBITER</h1>
          <p className="muted">Unified attack attribution for teleportation-based quantum digital signatures</p>
        </div>
        <div className="header-actions">
          {demoMode && <DemoMenu onSelect={(scenario) => void onDemoScenario(scenario)} />}
          <button type="button" className="secondary theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </button>
          <span className={`status ${online ? "ok" : online === false ? "bad" : ""}`} role="status">
            {online === null ? "connecting…" : online ? "API online" : "API offline: start uvicorn"}
          </span>
        </div>
      </header>

      <main className="grid">
        <section className="card span-3 accuracy-card">
          <AccuracyPanel demoCache={demoCache} />
        </section>

        <section className="card">
          <h2>Simulate a session</h2>
          <SessionForm busy={busy} onRun={onRun} onResubmit={onResubmit} />
          {error && <p className="error" role="alert">{error}</p>}
        </section>

        <section className="card span-2">
          <h2>Verdict</h2>
          {verdict ? <VerdictPanel verdict={verdict} /> : <p className="muted">Run a session to see the layered verdict.</p>}
        </section>

        <section className="card span-3">
          <h2>Sequential evidence</h2>
          {verdict?.layers.sequential.log_evidence ? (
            <EvidenceChart
              logEvidence={verdict.layers.sequential.log_evidence}
              logThreshold={verdict.layers.sequential.log_threshold}
              alarmAt={verdict.layers.sequential.rejected ? verdict.layers.sequential.stopped_at : null}
              attributedAt={verdict.layers.sequential.rejected ? verdict.layers.sequential.attributed_at : null}
            />
          ) : (
            <p className="muted">The anytime-valid log-evidence trajectory appears here.</p>
          )}
        </section>

        <section className="card span-2">
          <h2>Audit ledger</h2>
          <LedgerPanel version={ledgerVersion} highlight={verdict?.ledger?.index} demoMode={demoMode} report={tamperReport} />
        </section>

        <section className="card">
          <h2>Information-theoretic limits</h2>
          <BoundsTable />
        </section>
      </main>
    </div>
  );
}
