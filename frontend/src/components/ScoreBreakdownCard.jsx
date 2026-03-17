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
        <div className="score-total">
          <strong>{score.total_score}</strong>
          <span>{score.severity}</span>
        </div>
      </div>

      <div className="score-summary-grid">
        <div>
          <span className="label">Events</span>
          <strong>{score.summary.suspicious_event_count}</strong>
        </div>
        <div>
          <span className="label">Threat Intel Hits</span>
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
                <span style={{ width }} />
              </div>
              <p>{component.rationale}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}
