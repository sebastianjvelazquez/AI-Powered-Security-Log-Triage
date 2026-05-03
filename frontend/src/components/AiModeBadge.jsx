export default function AiModeBadge({ status }) {
  const provider = status?.provider || "unknown";
  const label = status?.mode_label || "Unavailable";
  const configured = status?.configured ?? false;

  const dotClass = `ai-badge-dot${!configured ? " unconfigured" : provider === "hosted" ? " hosted" : provider === "deterministic" ? " deterministic" : ""}`;

  return (
    <div
      className="ai-badge-compact"
      title={[status?.model, ...(status?.notes || [])].filter(Boolean).join(" · ") || "AI enrichment status"}
    >
      <span className={dotClass} aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
