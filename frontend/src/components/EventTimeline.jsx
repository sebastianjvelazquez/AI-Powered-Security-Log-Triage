import { useState } from "react";

function TimelineEvent({ event, sev }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <article
      className={`timeline-item${expanded ? " timeline-item-expanded" : ""}`}
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
      onClick={() => setExpanded((prev) => !prev)}
      style={{ cursor: "pointer" }}
      aria-expanded={expanded}
    >
      <div className={`timeline-marker ${sev}`} aria-hidden="true" />
      <div className="timeline-content">
        <header>
          <strong>{event.rule_name}</strong>
          <time>{event.timestamp || "No timestamp"}</time>
        </header>
        {expanded ? (
          <>
            <p style={{ marginTop: 4 }}>{event.reason}</p>
            <div className="timeline-meta">
              {event.source_ip ? <span className="timeline-tag">{event.source_ip}</span> : null}
              {event.user ? <span className="timeline-tag">{event.user}</span> : null}
              <span className="timeline-tag">{event.event_type}</span>
              <span className="timeline-tag">Risk {event.risk_weight}</span>
            </div>
          </>
        ) : (
          <p className="timeline-preview">{event.reason}</p>
        )}
      </div>
    </article>
  );
}

export default function EventTimeline({ events }) {
  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Timeline</p>
          <h3>Evidence Trail</h3>
        </div>
        {events.length > 0 ? <span className="count-pill">{events.length}</span> : null}
      </div>

      {events.length === 0 ? (
        <div className="empty-state compact">
          <p>No suspicious events are attached to this incident yet.</p>
        </div>
      ) : (
        <div className="timeline-list">
          {events.map((event, index) => {
            const sev =
              event.risk_weight >= 8
                ? "critical"
                : event.risk_weight >= 5
                  ? "high"
                  : event.risk_weight >= 3
                    ? "medium"
                    : "low";
            return (
              <TimelineEvent key={`${event.rule_name}-${index}`} event={event} sev={sev} />
            );
          })}
        </div>
      )}
    </section>
  );
}
