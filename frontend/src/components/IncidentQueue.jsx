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
        <span className="count-pill">{items.length} visible</span>
      </div>

      <div className="queue-filters">
        <input
          type="search"
          placeholder="Search title, file, or incident id"
          value={filters.search}
          onChange={(event) => onFilterChange("search", event.target.value)}
        />
        <div className="filter-grid">
          <select value={filters.severity} onChange={(event) => onFilterChange("severity", event.target.value)}>
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select value={filters.status} onChange={(event) => onFilterChange("status", event.target.value)}>
            <option value="all">All Statuses</option>
            <option value="new">New</option>
            <option value="in_review">In Review</option>
            <option value="escalated">Escalated</option>
            <option value="closed">Closed</option>
            <option value="false_positive">False Positive</option>
          </select>
          <select value={filters.source} onChange={(event) => onFilterChange("source", event.target.value)}>
            <option value="all">All Sources</option>
            <option value="auth">Auth</option>
            <option value="firewall">Firewall</option>
            <option value="windows">Windows</option>
            <option value="cloud">Cloud</option>
          </select>
          <select value={filters.mitre} onChange={(event) => onFilterChange("mitre", event.target.value)}>
            <option value="all">All MITRE</option>
            {mitreOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="queue-list">
        {items.length === 0 ? (
          <div className="empty-state compact">
            <p>No incidents match the current filters.</p>
          </div>
        ) : (
          items.map((item) => (
            <button
              key={item.incident_id}
              type="button"
              className={item.incident_id === selectedIncidentId ? "queue-card selected" : "queue-card"}
              onClick={() => onSelect(item.incident_id)}
            >
              <div className="queue-card-header">
                <SeverityBadge severity={item.severity || "Low"} />
                <span className={`status-chip status-${item.status}`}>{item.status.replace("_", " ")}</span>
              </div>
              <h3>{item.title}</h3>
              <p className="queue-meta">
                Incident #{item.incident_id} · {item.source_type} · Risk {item.risk_score ?? "-"}
              </p>
              <p className="queue-meta">{item.filename || "Correlated incident"}</p>
              <div className="chip-row">
                {item.mitre_techniques.slice(0, 3).map((technique) => (
                  <span key={technique} className="mitre-chip">
                    {technique}
                  </span>
                ))}
              </div>
            </button>
          ))
        )}
      </div>
    </section>
  );
}
