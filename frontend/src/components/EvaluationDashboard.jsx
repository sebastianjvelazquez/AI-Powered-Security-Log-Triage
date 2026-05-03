import { AlertTriangle, CheckCircle, Shield, XCircle } from "lucide-react";

function averageRisk(items) {
  if (items.length === 0) {
    return 0;
  }
  const total = items.reduce((sum, item) => sum + (item.risk_score || 0), 0);
  return (total / items.length).toFixed(1);
}

export default function EvaluationDashboard({ items }) {
  const severityCounts = items.reduce(
    (accumulator, item) => {
      const key = item.severity || "Low";
      accumulator[key] = (accumulator[key] || 0) + 1;
      return accumulator;
    },
    {}
  );
  const statusCounts = items.reduce((accumulator, item) => {
    accumulator[item.status] = (accumulator[item.status] || 0) + 1;
    return accumulator;
  }, {});
  const mitreCounts = items.reduce((accumulator, item) => {
    item.mitre_techniques.forEach((technique) => {
      accumulator[technique] = (accumulator[technique] || 0) + 1;
    });
    return accumulator;
  }, {});
  const topMitre = Object.entries(mitreCounts)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);

  return (
    <section className="evaluation-view">
      <div className="metric-card-grid">
        <article className="metric-card">
          <div className="metric-card-icon">
            <Shield size={18} aria-hidden="true" />
          </div>
          <span className="label">Incidents</span>
          <strong>{items.length}</strong>
        </article>
        <article className="metric-card">
          <div className="metric-card-icon" style={{ color: "var(--medium)" }}>
            <AlertTriangle size={18} aria-hidden="true" />
          </div>
          <span className="label">Average Risk</span>
          <strong>{averageRisk(items)}</strong>
        </article>
        <article className="metric-card">
          <div className="metric-card-icon" style={{ color: "var(--critical)" }}>
            <XCircle size={18} aria-hidden="true" />
          </div>
          <span className="label">Escalated</span>
          <strong>{statusCounts.escalated || 0}</strong>
        </article>
        <article className="metric-card">
          <div className="metric-card-icon" style={{ color: "var(--low)" }}>
            <CheckCircle size={18} aria-hidden="true" />
          </div>
          <span className="label">False Positive</span>
          <strong>{statusCounts.false_positive || 0}</strong>
        </article>
      </div>

      <div className="evaluation-grid">
        <section className="workspace-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Severity Mix</p>
              <h2>Queue Distribution</h2>
            </div>
          </div>
          <div className="mini-list">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity} className="mini-card">
                <strong>{severity}</strong>
                <p>{count} incident(s)</p>
              </div>
            ))}
          </div>
        </section>

        <section className="workspace-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">ATT&amp;CK Coverage</p>
              <h2>Most Frequent Techniques</h2>
            </div>
          </div>
          <div className="mini-list">
            {topMitre.length === 0 ? (
              <div className="mini-card">
                <strong>No MITRE data</strong>
                <p>Populate the queue to evaluate coverage.</p>
              </div>
            ) : (
              topMitre.map(([technique, count]) => (
                <div key={technique} className="mini-card">
                  <strong>{technique}</strong>
                  <p>{count} incident(s)</p>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="workspace-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Benchmark Runner</p>
              <h2>Local Evaluation Path</h2>
            </div>
          </div>
          <div className="mini-list">
            <div className="mini-card">
              <strong>Dataset</strong>
              <p>
                <code>backend/evaluation/datasets/default/benchmark_manifest.json</code>
              </p>
            </div>
            <div className="mini-card">
              <strong>Command</strong>
              <p>
                <code>
                  python3 backend/scripts/run_benchmark.py --dataset
                  backend/evaluation/datasets/default/benchmark_manifest.json
                </code>
              </p>
            </div>
            <div className="mini-card">
              <strong>Reports</strong>
              <p>
                <code>backend/evaluation/reports/</code> will receive JSON and Markdown summaries.
              </p>
            </div>
          </div>
        </section>
      </div>
    </section>
  );
}
