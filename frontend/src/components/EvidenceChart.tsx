interface Props {
  logEvidence: number[];
  logThreshold: number;
  alarmAt: number | null;
  attributedAt: number | null;
}

const W = 900;
const H = 240;
const PAD = { l: 48, r: 16, t: 12, b: 32 };

// Plain-SVG line chart of log E_t with the log(1/alpha) threshold.
export default function EvidenceChart({ logEvidence, logThreshold, alarmAt, attributedAt }: Props) {
  const n = logEvidence.length;
  const shown = attributedAt ? Math.min(n, Math.max(attributedAt * 2, 200)) : n;
  const data = logEvidence.slice(0, shown);
  const yMin = Math.min(-10, ...data);
  const yMax = Math.max(logThreshold * 3, Math.min(Math.max(...data), 200));
  const x = (i: number) => PAD.l + (i / Math.max(shown - 1, 1)) * (W - PAD.l - PAD.r);
  const y = (v: number) => PAD.t + (1 - (Math.min(v, yMax) - yMin) / (yMax - yMin)) * (H - PAD.t - PAD.b);
  const path = data.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const ticks = [yMin, 0, logThreshold, yMax].map((v) => Math.round(v * 10) / 10);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label="Sequential log-evidence over rounds">
      {ticks.map((t) => (
        <g key={t}>
          <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} className="grid-line" />
          <text x={PAD.l - 6} y={y(t) + 4} textAnchor="end" className="tick">
            {t}
          </text>
        </g>
      ))}
      <line x1={PAD.l} x2={W - PAD.r} y1={y(logThreshold)} y2={y(logThreshold)} className="threshold" />
      <text x={W - PAD.r} y={y(logThreshold) - 5} textAnchor="end" className="tick">
        log(1/α)
      </text>
      <path d={path} className="series" />
      {alarmAt && alarmAt <= shown && (
        <g>
          <line x1={x(alarmAt - 1)} x2={x(alarmAt - 1)} y1={PAD.t} y2={H - PAD.b} className="marker" />
          <text x={x(alarmAt - 1) + 4} y={PAD.t + 12} className="tick">
            alarm @{alarmAt}
          </text>
        </g>
      )}
      {attributedAt && attributedAt <= shown && attributedAt !== alarmAt && (
        <g>
          <line x1={x(attributedAt - 1)} x2={x(attributedAt - 1)} y1={PAD.t} y2={H - PAD.b} className="marker alt" />
          <text x={x(attributedAt - 1) + 4} y={PAD.t + 26} className="tick">
            attributed @{attributedAt}
          </text>
        </g>
      )}
      <text x={(W + PAD.l) / 2} y={H - 6} textAnchor="middle" className="tick">
        round (showing {shown} of {n})
      </text>
    </svg>
  );
}
