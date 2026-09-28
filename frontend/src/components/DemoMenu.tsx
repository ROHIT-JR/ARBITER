import { useEffect, useState } from "react";

import { api, type DemoScenario } from "../api";

export default function DemoMenu({ onSelect }: { onSelect: (scenario: DemoScenario) => void }) {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.demoScenarios().then(
      (catalogue) => setScenarios(catalogue.scenarios),
      (reason: Error) => setError(reason.message),
    );
  }, []);

  if (error) return <p className="error">Demo menu unavailable: {error}</p>;
  if (!scenarios.length) return <p className="muted small">Loading seeded demo presets…</p>;

  return (
    <details className="demo-menu">
      <summary>Demo presets</summary>
      <p className="muted small">Seeded, local-only actions for a reliable five-minute walkthrough.</p>
      <div className="demo-actions">
        {scenarios.map((scenario) => {
          const unavailable = Boolean(scenario.optional && !scenario.cached_result);
          return (
            <button
              type="button"
              className="secondary"
              key={scenario.id}
              disabled={unavailable}
              title={unavailable ? "No hardware result is bundled with this build" : undefined}
              onClick={() => onSelect(scenario)}
            >
              {unavailable ? `${scenario.title} (not bundled)` : scenario.title}
            </button>
          );
        })}
      </div>
    </details>
  );
}
