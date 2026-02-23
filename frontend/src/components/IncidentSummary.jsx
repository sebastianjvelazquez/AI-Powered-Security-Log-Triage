import { getJsonReportUrl, getMarkdownReportUrl } from "../api";

function severityClass(severity) {
  return `severity-badge severity-${severity?.toLowerCase() || "low"}`;
}

export default function IncidentSummary({ incident }) {
  if (!incident) {
    return null;
  }

  const { upload_id: uploadId, filename, source_type: sourceType, suspicious_count: suspiciousCount, risk_score: riskScore, analysis } = incident;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Incident Summary</h2>
        <span className={severityClass(analysis.severity)}>{analysis.severity}</span>
      </div>
      <p><strong>File:</strong> {filename}</p>
      <p><strong>Source:</strong> {sourceType}</p>
      <p><strong>Suspicious Events:</strong> {suspiciousCount}</p>
      <p><strong>Risk Score:</strong> {riskScore}</p>
      <p><strong>Attack Type:</strong> {analysis.attack_type}</p>

      <h3>MITRE ATT&CK Techniques</h3>
      <ul>
        {analysis.mitre_techniques.map((technique) => (
          <li key={technique}>{technique}</li>
        ))}
      </ul>

      <h3>Analyst Summary</h3>
      <p>{analysis.analysis_summary}</p>

      <h3>Recommended Actions</h3>
      <ul>
        {analysis.recommended_actions.map((action) => (
          <li key={action}>{action}</li>
        ))}
      </ul>

      <div className="report-buttons">
        <a href={getJsonReportUrl(uploadId)} target="_blank" rel="noreferrer">Download JSON Report</a>
        <a href={getMarkdownReportUrl(uploadId)} target="_blank" rel="noreferrer">Download Markdown Report</a>
      </div>
    </section>
  );
}
