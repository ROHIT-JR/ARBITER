import { label, type ComparisonResult, type DetectorName, type Hypothesis } from "../api";

type Attack = Exclude<Hypothesis, "legitimate">;
type DisplayDetector = Exclude<DetectorName, "baseline_bonferroni">;

interface Props {
  results: ComparisonResult[];
  detector: "unified" | "baseline" | "both";
}

const ATTACKS: Attack[] = ["forgery", "impersonation", "replay", "channel_manipulation"];
const W = 920;
const H = 310;
const PAD = { l: 54, r: 18, t: 18, b: 44 };

export default function ThetaCurve({ results, detector }: Props) {
  const ordered = [...results].sort((a, b) => a.metadata.theta - b.metadata.theta);
  const detectors: DisplayDetector[] = detector === "both" ? ["unified", "baseline"] : [detector];
  const x = (theta: number) => PAD.l + ((theta - 0.05) / 0.95) * (W - PAD.l - PAD.r);
  const y = (rate: number) => PAD.t + (1 - rate) * (H - PAD.t - PAD.b);
  const xTicks = [0.05, 0.25, 0.5, 0.75, 1];
  const yTicks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="curve-panel">
      <div className="curve-head">
        <div>
          <h3>Correct attribution vs attack strength</h3>
          <p className="muted small">Solid lines are ARBITER; dashed lines are fixed thresholds.</p>
        </div>
        <ul className="curve-legend" aria-label="Attack legend">
          {ATTACKS.map((attack) => (
            <li key={attack}><span className={`legend-swatch attack-${attack}`} />{label(attack)}</li>
          ))}
        </ul>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart theta-chart" role="img" aria-label="Correct attribution rate by attack strength and detector">
        {yTicks.map((tick) => (
          <g key={`y-${tick}`}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(tick)} y2={y(tick)} className="grid-line" />
            <text x={PAD.l - 8} y={y(tick) + 4} textAnchor="end" className="tick">{Math.round(tick * 100)}%</text>
          </g>
        ))}
        {xTicks.map((tick) => (
          <g key={`x-${tick}`}>
            <line x1={x(tick)} x2={x(tick)} y1={PAD.t} y2={H - PAD.b} className="grid-line" />
            <text x={x(tick)} y={H - PAD.b + 20} textAnchor="middle" className="tick">{tick}</text>
          </g>
        ))}
        {detectors.flatMap((detectorName) =>
          ATTACKS.map((attack) => {
            const points = ordered.map((result) => ({
              theta: result.metadata.theta,
              rate: result.detectors[detectorName].attacks[attack].correct_attribution_rate,
            }));
            const path = points.map((point, index) => `${index ? "L" : "M"}${x(point.theta).toFixed(1)},${y(point.rate).toFixed(1)}`).join("");
            return (
              <g key={`${detectorName}-${attack}`} className={`curve-series attack-${attack} ${detectorName === "baseline" ? "baseline" : ""}`}>
                <title>{`${detectorName === "unified" ? "ARBITER" : "Fixed thresholds"}: ${label(attack)}`}</title>
                <path d={path} />
                {points.map((point) => <circle key={point.theta} cx={x(point.theta)} cy={y(point.rate)} r={3} />)}
              </g>
            );
          }),
        )}
        <text x={(W + PAD.l - PAD.r) / 2} y={H - 5} textAnchor="middle" className="tick axis-label">attack strength θ</text>
      </svg>
    </div>
  );
}
