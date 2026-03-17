export default function EventTimeline({ events }) {
  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Timeline</p>
          <h3>Evidence Trail</h3>
        </div>
      </div>

      {events.length === 0 ? (
        <div className="empty-state compact">
          <p>No suspicious events are attached to this incident yet.</p>
        </div>
      ) : (
        <div className="timeline-list">
          {events.map((event, index) => (
            <article key={`${event.rule_name}-${index}`} className="timeline-item">
              <div className="timeline-marker" />
              <div className="timeline-content">
                <header>
                  <strong>{event.rule_name}</strong>
                  <span>{event.timestamp || "No timestamp"}</span>
                </header>
                <p>{event.reason}</p>
                <div className="timeline-meta">
                  <span>{event.source_ip || "No source IP"}</span>
                  <span>{event.user || "No user"}</span>
                  <span>{event.event_type}</span>
                  <span>Risk {event.risk_weight}</span>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
