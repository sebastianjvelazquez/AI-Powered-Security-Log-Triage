import { useState } from "react";
import { Brain, ChevronDown, ChevronRight, Globe } from "lucide-react";

function ThreatIntelView({ payload }) {
  return (
    <>
      <div className="metric-strip" style={{ gridTemplateColumns: "repeat(3, 1fr)", marginBottom: 9 }}>
        <div>
          <span className="label">Indicators</span>
          <strong>{payload.summary.indicators_evaluated}</strong>
        </div>
        <div>
          <span className="label">Malicious</span>
          <strong style={{ color: "var(--critical)" }}>{payload.summary.malicious_indicator_count}</strong>
        </div>
        <div>
          <span className="label">TOR / VPN</span>
          <strong>{payload.summary.tor_vpn_count}</strong>
        </div>
      </div>
      <table className="enrichment-table">
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Country</th>
            <th>ASN</th>
            <th>Score</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {payload.indicators.map((indicator) => (
            <tr key={indicator.indicator}>
              <td style={{ fontFamily: "monospace", fontSize: "0.65rem" }}>{indicator.indicator}</td>
              <td>{indicator.country || "—"}</td>
              <td>{indicator.asn || "—"}</td>
              <td>{indicator.reputation_score}</td>
              <td style={{ color: indicator.is_malicious ? "var(--critical)" : "var(--low)" }}>
                {indicator.is_malicious ? "Malicious" : "Clean"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function TraceView({ payload }) {
  return (
    <div className="mini-list">
      <div className="mini-card">
        <strong>{payload.provider}</strong>
        <p>
          {payload.model} · prompt {payload.prompt_version}
        </p>
        <p>Fallback used: {String(payload.used_fallback)}</p>
      </div>
      {payload.tasks.map((task) => (
        <div key={task.task_name} className="mini-card">
          <strong>{task.task_name}</strong>
          <p>{task.prompt_name}</p>
          <p>{task.used_fallback ? task.validation_error || "Fallback applied" : "Validated successfully"}</p>
        </div>
      ))}
    </div>
  );
}

function EnrichmentCard({ enrichment }) {
  const [showRaw, setShowRaw] = useState(false);
  const isIntel = enrichment.enrichment_type === "threat_intel";
  const isTrace = enrichment.enrichment_type === "llm_execution_trace";
  const Icon = isTrace ? Brain : Globe;

  return (
    <article className="enrichment-card">
      <div className="enrichment-card-header">
        <Icon size={13} style={{ color: "var(--accent)", flexShrink: 0 }} aria-hidden="true" />
        <strong>{enrichment.enrichment_type.replaceAll("_", " ")}</strong>
        <span>{enrichment.provider}</span>
      </div>
      <div className="enrichment-card-body">
        {enrichment.summary ? <p className="enrichment-summary">{enrichment.summary}</p> : null}
        {isIntel ? (
          <ThreatIntelView payload={enrichment.payload} />
        ) : isTrace ? (
          <TraceView payload={enrichment.payload} />
        ) : (
          <>
            <button
              type="button"
              className="enrichment-raw-toggle"
              onClick={() => setShowRaw((prev) => !prev)}
              aria-expanded={showRaw}
            >
              {showRaw ? (
                <ChevronDown size={11} aria-hidden="true" />
              ) : (
                <ChevronRight size={11} aria-hidden="true" />
              )}
              {showRaw ? "Hide" : "Show"} raw data
            </button>
            {showRaw ? (
              <pre className="enrichment-pre">{JSON.stringify(enrichment.payload, null, 2)}</pre>
            ) : null}
          </>
        )}
      </div>
    </article>
  );
}

export default function EnrichmentPanel({ enrichments }) {
  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Enrichment</p>
          <h3>Context Layers</h3>
        </div>
        {enrichments.length > 0 ? <span className="count-pill">{enrichments.length}</span> : null}
      </div>

      {enrichments.length === 0 ? (
        <div className="empty-state compact">
          <p>No enrichments have been persisted for this incident.</p>
        </div>
      ) : (
        <div className="enrichment-stack">
          {enrichments.map((enrichment) => (
            <EnrichmentCard
              key={`${enrichment.enrichment_type}-${enrichment.created_at}`}
              enrichment={enrichment}
            />
          ))}
        </div>
      )}
    </section>
  );
}
