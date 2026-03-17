export default function SeverityBadge({ severity }) {
  const normalized = severity ? severity.toLowerCase() : "low";
  return <span className={`severity-badge severity-${normalized}`}>{severity || "Low"}</span>;
}
