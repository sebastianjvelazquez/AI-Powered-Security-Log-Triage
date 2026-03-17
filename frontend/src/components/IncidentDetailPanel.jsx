import { getJsonReportUrl, getMarkdownReportUrl } from "../api";
import SeverityBadge from "./SeverityBadge";
import ScoreBreakdownCard from "./ScoreBreakdownCard";

export default function IncidentDetailPanel({ incident }) {
  if (!incident) {
    return (
      <section className="workspace-panel detail-panel">
        <div className="empty-state tall">
          <p>Select an incident from the queue to inspect evidence, scoring, and analyst actions.</p>
        </div>
      </section>
    );
  }

  const reportUploadId = incident.upload_id;

  return (
    <section className="workspace-panel detail-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Selected Incident</p>
          <h2>{incident.title}</h2>
          <p className="detail-subtitle">
            Incident #{incident.incident_id} · {incident.source_type} · {incident.filename || "Correlated evidence"}
          </p>
        </div>
        <div className="detail-badges">
          <SeverityBadge severity={incident.effective_severity || incident.analysis?.severity || "Low"} />
          <span className={`status-chip status-${incident.status}`}>{incident.status.replace("_", " ")}</span>
        </div>
      </div>

      <div className="detail-grid">
        <div className="subpanel">
          <div className="metric-strip">
            <div>
              <span className="label">Suspicious Events</span>
              <strong>{incident.suspicious_count}</strong>
            </div>
            <div>
              <span className="label">Latest Disposition</span>
              <strong>{incident.latest_disposition || "Unreviewed"}</strong>
            </div>
            <div>
              <span className="label">Upload Time</span>
              <strong>{new Date(incident.uploaded_at).toLocaleString()}</strong>
            </div>
          </div>

          <h3>Analyst Summary</h3>
          <p>{incident.analysis?.analysis_summary || "No analyst summary is available."}</p>

          <h3>MITRE ATT&CK</h3>
          <div className="chip-row">
            {(incident.effective_mitre_techniques || []).map((technique) => (
              <span key={technique} className="mitre-chip">
                {technique}
              </span>
            ))}
          </div>

          <h3>Recommended Actions</h3>
          <ul className="action-list">
            {(incident.effective_recommended_actions || []).map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>

          <div className="report-buttons">
            {reportUploadId ? (
              <>
                <a href={getJsonReportUrl(reportUploadId)} target="_blank" rel="noreferrer">
                  Download JSON
                </a>
                <a href={getMarkdownReportUrl(reportUploadId)} target="_blank" rel="noreferrer">
                  Download Markdown
                </a>
              </>
            ) : (
              <span className="muted-copy">Reports are available on the primary upload artifact.</span>
            )}
          </div>
        </div>

        <ScoreBreakdownCard score={incident.score} />
      </div>
    </section>
  );
}
