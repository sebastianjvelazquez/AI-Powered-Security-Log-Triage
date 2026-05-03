import { Download, Shield } from "lucide-react";
import { downloadIncidentReport } from "../api";
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
      <div className="incident-header-bar">
        <span className="incident-id-tag">#{incident.incident_id}</span>
        <SeverityBadge severity={incident.effective_severity || incident.analysis?.severity || "Low"} />
        <span className={`status-chip status-${incident.status}`}>
          {incident.status.replace(/_/g, " ")}
        </span>
        <span className="detail-subtitle" style={{ marginLeft: "auto" }}>
          {incident.source_type} · {new Date(incident.uploaded_at).toLocaleString()}
        </span>
      </div>

      <div className="panel-heading" style={{ marginBottom: 10 }}>
        <h2>{incident.title}</h2>
      </div>

      <div className="detail-grid">
        <div style={{ display: "grid", gap: 12 }}>
          <div className="metric-strip">
            <div>
              <span className="label">Events</span>
              <strong>{incident.suspicious_count}</strong>
            </div>
            <div>
              <span className="label">Disposition</span>
              <strong style={{ fontSize: "0.78rem" }}>{incident.latest_disposition || "Unreviewed"}</strong>
            </div>
          </div>

          <div>
            <p className="eyebrow" style={{ marginBottom: 5 }}>Analyst Summary</p>
            <div className="analyst-summary-card">
              <p>{incident.analysis?.analysis_summary || "No analyst summary is available."}</p>
            </div>
          </div>

          <div>
            <p className="eyebrow" style={{ marginBottom: 5, display: "flex", alignItems: "center", gap: 4 }}>
              <Shield size={10} aria-hidden="true" /> MITRE ATT&amp;CK
            </p>
            <div className="mitre-strip">
              {(incident.effective_mitre_techniques || []).map((technique) => (
                <span key={technique} className="mitre-chip">
                  {technique}
                </span>
              ))}
            </div>
          </div>

          <div>
            <p className="eyebrow" style={{ marginBottom: 5 }}>Recommended Actions</p>
            <ul className="action-checklist">
              {(incident.effective_recommended_actions || []).map((action) => (
                <li key={action}>
                  <span style={{ color: "var(--accent)", flexShrink: 0 }}>›</span>
                  {action}
                </li>
              ))}
            </ul>
          </div>

          <div className="report-buttons">
            {reportUploadId ? (
              <>
                <button
                  type="button"
                  className="icon-button"
                  onClick={() => downloadIncidentReport(reportUploadId, "json")}
                >
                  <Download size={12} aria-hidden="true" /> JSON Report
                </button>
                <button
                  type="button"
                  className="icon-button"
                  onClick={() => downloadIncidentReport(reportUploadId, "markdown")}
                >
                  <Download size={12} aria-hidden="true" /> Markdown Report
                </button>
              </>
            ) : (
              <span className="muted-copy">Reports available on primary upload artifact.</span>
            )}
          </div>
        </div>

        <ScoreBreakdownCard score={incident.score} />
      </div>
    </section>
  );
}
