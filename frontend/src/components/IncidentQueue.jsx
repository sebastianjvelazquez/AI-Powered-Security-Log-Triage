import { Search } from "lucide-react";
import SeverityBadge from "./SeverityBadge";

export default function IncidentQueue({
  items,
  filters,
  mitreOptions,
  selectedIncidentId,
  onFilterChange,
  onSelect
}) {
  return (
    <section className="workspace-panel queue-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Queue</p>
          <h2>Incident Intake</h2>
        </div>
        <span className="count-pill">{items.length}</span>
      </div>

      <div className="queue-filters">
        <div style={{ position: "relative" }}>
          <Search
            size={12}
            style={{ position: "absolute", left: 8, top: "50%", transform: "translateY(-50%)", color: "var(--muted)", pointerEvents: "none" }}
            aria-hidden="true"
          />
          <input
            type="search"
            placeholder="Search title, file, or incident id"
            value={filters.search}
            style={{ paddingLeft: 26 }}
            onChange={(event) => onFilterChange("search", event.target.value)}
            aria-label="Search incidents"
          />
        </div>
        <div className="filter-row">
          <select value={filters.severity} onChange={(event) => onFilterChange("severity", event.target.value)} aria-label="Filter by severity">
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select value={filters.status} onChange={(event) => onFilterChange("status", event.target.value)} aria-label="Filter by status">
            <option value="all">All Statuses</option>
            <option value="new">New</option>
            <option value="in_review">In Review</option>
            <option value="escalated">Escalated</option>
            <option value="closed">Closed</option>
            <option value="false_positive">False Positive</option>
          </select>
          <select value={filters.source} onChange={(event) => onFilterChange("source", event.target.value)} aria-label="Filter by source">
            <option value="all">All Sources</option>
            <option value="auth">Auth</option>
            <option value="firewall">Firewall</option>
            <option value="windows">Windows</option>
            <option value="cloud">Cloud</option>
          </select>
          <select value={filters.mitre} onChange={(event) => onFilterChange("mitre", event.target.value)} aria-label="Filter by MITRE technique">
            <option value="all">All MITRE</option>
            {mitreOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="queue-list" role="list">
        {items.length === 0 ? (
          <div className="empty-state compact">
            <p>No incidents match the current filters.</p>
          </div>
        ) : (
          items.map((item) => {
            const sev = (item.severity || "low").toLowerCase();
            const riskColor =
              sev === "critical" ? "var(--critical)"
              : sev === "high" ? "var(--high)"
              : sev === "medium" ? "var(--medium)"
              : "var(--low)";
            return (
              <button
                key={item.incident_id}
                type="button"
                role="listitem"
                className={`queue-card sev-${sev}${item.incident_id === selectedIncidentId ? " selected" : ""}`}
                onClick={() => onSelect(item.incident_id)}
                aria-pressed={item.incident_id === selectedIncidentId}
              >
                <div className="queue-card-header">
                  <div className="queue-card-title-row">
                    <SeverityBadge severity={item.severity || "Low"} variant="dot" />
                    <span className="queue-meta">#{item.incident_id}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                    <span style={{ fontSize: "0.8rem", fontWeight: 700, color: riskColor }}>
                      {item.risk_score ?? "-"}
                    </span>
                    <span className={`status-chip status-${item.status}`}>
                      {item.status.replace(/_/g, " ")}
                    </span>
                  </div>
                </div>
                <h3>{item.title}</h3>
                <p className="queue-meta">
                  {item.source_type} · {item.filename || "Correlated incident"}
                </p>
                {item.mitre_techniques.length > 0 ? (
                  <div className="chip-row" style={{ marginTop: 5 }}>
                    {item.mitre_techniques.slice(0, 3).map((technique) => (
                      <span key={technique} className="mitre-chip">
                        {technique}
                      </span>
                    ))}
                  </div>
                ) : null}
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}
