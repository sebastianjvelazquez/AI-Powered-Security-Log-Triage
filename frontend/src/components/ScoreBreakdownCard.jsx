function ScoreRing({ score, maxScore, severity }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const pct = maxScore ? Math.min(score / maxScore, 1) : 0;
  const offset = circumference * (1 - pct);

  const color =
    pct >= 0.8
      ? "var(--critical)"
      : pct >= 0.6
        ? "var(--high)"
        : pct >= 0.4
          ? "var(--medium)"
          : "var(--accent)";

  return (
    <div style={{ display: "flex", justifyContent: "center", padding: "10px 0" }}>
      <svg width="96" height="96" viewBox="0 0 100 100" aria-label={`Risk score: ${score} out of ${maxScore}`}>
        <circle cx="50" cy="50" r={radius} fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth="8" />
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 50 50)"
          style={{ transition: "stroke-dashoffset 500ms ease" }}
        />
        <text
          x="50"
          y="46"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fill: "var(--text)", fontSize: "18px", fontWeight: 700 }}
        >
          {score}
        </text>
        <text x="50" y="62" textAnchor="middle" style={{ fill: "var(--muted)", fontSize: "8px" }}>
          {severity || ""}
        </text>
      </svg>
    </div>
  );
}

export default function ScoreBreakdownCard({ score }) {
  if (!score) {
    return (
      <section className="subpanel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Scoring</p>
            <h3>Risk Breakdown</h3>
          </div>
        </div>
        <div className="empty-state compact">
          <p>No score breakdown is available yet.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Scoring</p>
          <h3>Risk Breakdown</h3>
        </div>
      </div>

      <ScoreRing score={score.total_score} maxScore={100} severity={score.severity} />

      <div className="score-summary-grid">
        <div>
          <span className="label">Events</span>
          <strong>{score.summary.suspicious_event_count}</strong>
        </div>
        <div>
          <span className="label">Intel Hits</span>
          <strong>{score.summary.threat_intel_hits}</strong>
        </div>
        <div>
          <span className="label">Correlation</span>
          <strong>{score.summary.correlation_strength}</strong>
        </div>
      </div>

      <div className="score-components">
        {score.breakdown.map((component) => {
          const width = component.max_score ? `${(component.score / component.max_score) * 100}%` : "0%";
          return (
            <div key={component.component} className="score-component">
              <div className="score-component-header">
                <span>{component.component.replaceAll("_", " ")}</span>
                <strong>
                  {component.score}/{component.max_score}
                </strong>
              </div>
              <div className="score-bar">
                <span style={{ width }} aria-hidden="true" />
              </div>
              <p>{component.rationale}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}
