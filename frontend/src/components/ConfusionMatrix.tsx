import { HYPOTHESES, label, type DetectorComparison } from "../api";

interface Props {
  title: string;
  result: DetectorComparison;
  sessions: number;
}

const SHORT_LABELS = {
  legitimate: "Legit.",
  forgery: "Forgery",
  impersonation: "Imperson.",
  replay: "Replay",
  channel_manipulation: "Channel",
} as const;

export default function ConfusionMatrix({ title, result, sessions }: Props) {
  return (
    <article className="matrix-panel">
      <div className="matrix-head">
        <h3>{title}</h3>
        <span className="metric-chip">FAR {(result.false_alarm_rate * 100).toFixed(1)}%</span>
      </div>
      <div className="matrix-scroll">
        <table className="confusion-matrix">
          <caption className="sr-only">{title} confusion matrix. Rows are true scenarios and columns are attributed scenarios.</caption>
          <thead>
            <tr>
              <th scope="col">Truth ↓</th>
              {HYPOTHESES.map((hypothesis) => (
                <th scope="col" key={hypothesis} title={label(hypothesis)}>
                  {SHORT_LABELS[hypothesis]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {HYPOTHESES.map((truth) => (
              <tr key={truth}>
                <th scope="row" title={label(truth)}>{SHORT_LABELS[truth]}</th>
                {HYPOTHESES.map((prediction) => {
                  const value = result.confusion_matrix[truth][prediction];
                  const bucket = Math.min(10, Math.round((value / sessions) * 10));
                  return (
                    <td
                      key={prediction}
                      className={`heat heat-${bucket}`}
                      title={`${label(truth)} attributed as ${label(prediction)}: ${value} of ${sessions}`}
                    >
                      {value}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small matrix-note">Counts out of {sessions}. Darker cells indicate a larger share of the row.</p>
    </article>
  );
}
