export default function AiModeBadge({ status }) {
  const provider = status?.provider || "unknown";
  const label = status?.mode_label || "AI status unavailable";
  const configured = status?.configured ?? false;
  const className = `ai-mode-badge ai-mode-${provider} ${configured ? "is-configured" : "is-unconfigured"}`;

  return (
    <div className={className} title={status?.notes?.join(" ") || "AI enrichment status"}>
      <span className="ai-mode-dot" aria-hidden="true" />
      <div>
        <span className="label">AI Mode</span>
        <strong>{label}</strong>
        <small>{status?.model || "No provider configured"}</small>
      </div>
    </div>
  );
}
