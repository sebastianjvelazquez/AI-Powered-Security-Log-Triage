export default function HistoryTable({ items }) {
  return (
    <section className="panel">
      <h2>Incident History</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>File</th>
              <th>Source</th>
              <th>Suspicious</th>
              <th>Severity</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.upload_id}>
                <td>{item.upload_id}</td>
                <td>{item.filename}</td>
                <td>{item.source_type}</td>
                <td>{item.suspicious_count}</td>
                <td>{item.severity || "-"}</td>
                <td>{item.risk_score ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
