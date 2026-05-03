import SeverityBadge from "./SeverityBadge";

export default function RelatedIncidentsPanel({ currentIncident, history, onSelectIncident }) {
  if (!currentIncident) {
    return (
      <section className="subpanel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Related</p>
            <h3>Incident Neighbors</h3>
          </div>
        </div>
        <div className="empty-state compact">
          <p>Select an incident to explore related queue activity.</p>
        </div>
      </section>
    );
  }

  const currentMitre = new Set(currentIncident.effective_mitre_techniques || []);
  const related = history
    .filter((item) => item.incident_id !== currentIncident.incident_id)
    .filter((item) => {
      const sourceMatch = item.source_type === currentIncident.source_type;
      const mitreMatch = item.mitre_techniques.some((technique) => currentMitre.has(technique));
      return sourceMatch || mitreMatch;
    })
    .slice(0, 5);

  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Related</p>
          <h3>Incident Neighbors</h3>
        </div>
        {related.length > 0 ? <span className="count-pill">{related.length}</span> : null}
      </div>

      {related.length === 0 ? (
        <div className="empty-state compact">
          <p>No nearby incidents matched the current source or MITRE profile.</p>
        </div>
      ) : (
        <div className="mini-list">
          {related.map((item) => {
            const sharedTech = item.mitre_techniques.filter((t) => currentMitre.has(t));
            return (
              <button
                key={item.incident_id}
                type="button"
                className="mini-card interactive"
                onClick={() => onSelectIncident(item.incident_id)}
              >
                <div className="mini-card-row" style={{ marginBottom: 3 }}>
                  <SeverityBadge severity={item.severity || "Low"} variant="dot" />
                  <strong style={{ flex: 1 }}>{item.title}</strong>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--muted)" }}>
                    {item.risk_score ?? "-"}
                  </span>
                </div>
                <p style={{ paddingLeft: 14 }}>
                  #{item.incident_id} · {item.source_type} · {item.status.replace(/_/g, " ")}
                </p>
                {sharedTech.length > 0 ? (
                  <div style={{ paddingLeft: 14 }}>
                    <span className="count-pill">
                      {sharedTech.length} shared technique{sharedTech.length > 1 ? "s" : ""}
                    </span>
                  </div>
                ) : null}
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
