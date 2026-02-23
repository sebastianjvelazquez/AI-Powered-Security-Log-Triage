export default function EventsTable({ events }) {
  if (!events || events.length === 0) {
    return null;
  }

  return (
    <section className="panel">
      <h2>Parsed Suspicious Events</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Event Type</th>
              <th>Status</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, index) => (
              <tr key={`${event.rule_name}-${index}`}>
                <td>{event.rule_name}</td>
                <td>{event.timestamp || "-"}</td>
                <td>{event.source_ip || "-"}</td>
                <td>{event.user || "-"}</td>
                <td>{event.event_type}</td>
                <td>{event.status || "-"}</td>
                <td>{event.risk_weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
