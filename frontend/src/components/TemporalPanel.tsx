import type { Verdict } from "../api";

interface Props {
  temporal: Verdict["layers"]["temporal"];
}

const W = 900;
const H = 250;
const PAD = { l: 42, r: 18, t: 24, b: 34 };
const SERIES = {
  signature: "temporal-signature",
  freshness: "temporal-freshness",
  chsh: "temporal-chsh",
} as const;

export default function TemporalPanel({ temporal }: Props) {
  const entries = Object.entries(temporal.streams) as [keyof typeof SERIES, (typeof temporal.streams)["signature"]][];
  const maxRound = Math.max(1, ...entries.flatMap(([, stream]) => stream.windows.map((window) => window.stop)));
  const x = (round: number) => PAD.l + (round / maxRound) * (W - PAD.l - PAD.r);
  const y = (rate: number) => PAD.t + (1 - rate) * (H - PAD.t - PAD.b);

  return (
    <div className="temporal-panel">
      <div className="temporal-heading">
        <div>
          <h2>Temporal mismatch rates</h2>
          <p className="muted small">Sliding-window diagnostics; no machine-learning classifier.</p>
        </div>
        <span className={`metric-chip ${temporal.rejected ? "temporal-alert" : ""}`}>
          {temporal.rejected ? "structure flagged" : "no structure flagged"}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart temporal-chart" role="img" aria-label="Windowed mismatch rates by round type">
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => (
          <g key={tick}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(tick)} y2={y(tick)} className="grid-line" />
            <text x={PAD.l - 7} y={y(tick) + 4} textAnchor="end" className="tick">{Math.round(tick * 100)}%</text>
          </g>
        ))}
        {entries.map(([name, stream]) => {
          const path = stream.windows.map((window, index) => `${index ? "L" : "M"}${x(window.start + window.count / 2).toFixed(1)},${y(window.mismatch_rate).toFixed(1)}`).join("");
          return <path key={name} d={path} className={`temporal-series ${SERIES[name]}`} />;
        })}
        <text x={(W + PAD.l) / 2} y={H - 6} textAnchor="middle" className="tick">round within type stream</text>
      </svg>
      <div className="temporal-legend" aria-label="Temporal test details">
        {entries.map(([name, stream]) => (
          <div key={name} className="temporal-stream">
            <span className={`temporal-dot ${SERIES[name]}`} aria-hidden="true" />
            <strong>{name}</strong>
            <span>{stream.rounds} rounds</span>
            <span className={stream.flagged ? "flag" : "muted"}>{stream.flagged ? "flagged" : "clear"}</span>
            <span>run {stream.burst.longest_run.statistic}/{stream.burst.longest_run.threshold}</span>
            <span>g {stream.spectral.fisher_g.statistic.toFixed(3)}</span>
          </div>
        ))}
      </div>
      <p className="muted small temporal-note">{temporal.multiple_testing}; family α={temporal.alpha}, per-test α={temporal.per_test_alpha.toFixed(4)}.</p>
    </div>
  );
}
