import { useCallback, useEffect, useState } from "react";

import { api, type ComparisonResult, type DemoAccuracyCache } from "../api";
import ConfusionMatrix from "./ConfusionMatrix";
import ThetaCurve from "./ThetaCurve";

type DetectorChoice = "unified" | "baseline" | "both";

const SEED = 26141;
const CURVE_THETAS = [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1];

const ATTACKS = ["forgery", "impersonation", "replay", "channel_manipulation"] as const;

function expandDemoCache(cache: DemoAccuracyCache): ComparisonResult[] {
  return cache.curve.map((point) => {
    const detector = (name: "unified" | "baseline") => ({
      ...cache.detectors[name],
      attacks: Object.fromEntries(
        ATTACKS.map((attack, index) => [attack, {
          detection_rate: point[name][index],
          correct_attribution_rate: point[name][index],
        }]),
      ) as ComparisonResult["detectors"]["unified"]["attacks"],
    });
    return {
      ...cache,
      metadata: { ...cache.metadata, theta: point.theta },
      detectors: {
        unified: detector("unified"),
        baseline: detector("baseline"),
        baseline_bonferroni: detector("baseline"),
      },
    };
  });
}

export default function AccuracyPanel({ demoCache }: { demoCache?: DemoAccuracyCache | null }) {
  const [theta, setTheta] = useState(0.3);
  const [sessions, setSessions] = useState(40);
  const [detector, setDetector] = useState<DetectorChoice>("both");
  const [query, setQuery] = useState({ theta, sessions });
  const [results, setResults] = useState<ComparisonResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!demoCache) return;
    setTheta(demoCache.metadata.theta);
    setSessions(demoCache.metadata.sessions_per_hypothesis);
    setQuery({ theta: demoCache.metadata.theta, sessions: demoCache.metadata.sessions_per_hypothesis });
    setError(null);
  }, [demoCache]);

  const load = useCallback(async () => {
    setLoading(true);
    setResults(null);
    setError(null);
    const points = [...new Set([...CURVE_THETAS, query.theta])].sort((a, b) => a - b);
    try {
      setResults(await Promise.all(points.map((point) => api.compare(point, query.sessions, SEED))));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    if (demoCache) return;
    void load();
  }, [demoCache, load]);

  const displayedResults = demoCache ? expandDemoCache(demoCache) : results;
  const selected = displayedResults?.find((result) => result.metadata.theta === query.theta);
  const shownDetectors = detector === "both" ? ["unified", "baseline"] as const : [detector] as const;

  return (
    <div className="accuracy-panel">
      <div className="accuracy-intro" id="accuracy-panel">
        <div>
          <h2>Accuracy across sessions</h2>
          <p className="muted">Compare one joint test with four fixed thresholds under the same sessions and false-alarm target.</p>
        </div>
        <span className="metric-chip">{demoCache ? "cached demo data" : `seed ${SEED}`}</span>
      </div>

      <form
        className="accuracy-controls"
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          setQuery({ theta, sessions });
        }}
      >
        <label>
          <span>Selected strength θ <output>{theta.toFixed(2)}</output></span>
          <input type="range" min={0.05} max={1} step={0.05} value={theta} onChange={(event) => setTheta(Number(event.target.value))} />
        </label>
        <label>
          Sessions / hypothesis
          <input type="number" min={20} max={200} step={10} value={sessions} onChange={(event) => setSessions(Number(event.target.value))} />
        </label>
        <label>
          Detector
          <select value={detector} onChange={(event) => setDetector(event.target.value as DetectorChoice)}>
            <option value="unified">ARBITER</option>
            <option value="baseline">fixed thresholds</option>
            <option value="both">both</option>
          </select>
        </label>
        <button type="submit" disabled={loading || Boolean(demoCache)}>{demoCache ? "Cached demo result" : "Run comparison"}</button>
      </form>

      {error && (
        <div className="accuracy-error" role="alert">
          <p className="error">{error}</p>
          <button type="button" className="secondary" onClick={() => void load()} disabled={loading}>Try again</button>
        </div>
      )}

      {loading && !demoCache && (
        <div className="accuracy-loading" role="status" aria-live="polite" aria-busy="true">
          <span className="loading-mark" aria-hidden="true" />
          <div>
            <strong>Running paired simulations…</strong>
            <p className="muted small">Seven θ values × five hypotheses. This usually takes 5–15 seconds.</p>
          </div>
        </div>
      )}

      {displayedResults && selected && (
        <>
          <div className={`matrix-grid ${shownDetectors.length === 1 ? "single" : ""}`}>
            {shownDetectors.map((name) => (
              <ConfusionMatrix
                key={name}
                title={name === "unified" ? "ARBITER unified GLRT" : "Four fixed thresholds"}
                result={selected.detectors[name]}
                sessions={query.sessions}
              />
            ))}
          </div>
          <ThetaCurve results={displayedResults} detector={detector} />
          <p className="muted small accuracy-footnote">
            Balanced 1,200-round sessions at α = {selected.metadata.alpha}. Impersonation is all-or-nothing, so its line is constant.
          </p>
        </>
      )}
    </div>
  );
}
