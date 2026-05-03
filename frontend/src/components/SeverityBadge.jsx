export default function SeverityBadge({ severity, variant = "pill" }) {
  const normalized = severity ? severity.toLowerCase() : "low";
  const label = severity || "Low";

  if (variant === "dot") {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
        <span className={`severity-dot ${normalized}`} aria-hidden="true" />
        <span style={{ fontSize: "0.75rem", fontWeight: 600, color: `var(--${normalized})` }}>{label}</span>
      </span>
    );
  }

  return (
    <span className={`severity-badge severity-${normalized}`}>
      <span className={`severity-dot ${normalized}`} aria-hidden="true" />
      {label}
    </span>
  );
}
