function renderThreatIntel(payload) {
  return (
    <>
      <div className="metric-strip compact-strip">
        <div>
          <span className="label">Indicators</span>
          <strong>{payload.summary.indicators_evaluated}</strong>
        </div>
        <div>
          <span className="label">Malicious</span>
          <strong>{payload.summary.malicious_indicator_count}</strong>
        </div>
        <div>
          <span className="label">TOR / VPN</span>
          <strong>{payload.summary.tor_vpn_count}</strong>
        </div>
      </div>
      <div className="mini-list">
        {payload.indicators.map((indicator) => (
          <div key={indicator.indicator} className="mini-card">
            <strong>{indicator.indicator}</strong>
            <p>
              {indicator.country || "Unknown"} · {indicator.asn || "Unknown ASN"}
            </p>
            <p>
              Reputation {indicator.reputation_score} · malicious {String(indicator.is_malicious)}
            </p>
          </div>
        ))}
      </div>
    </>
  );
}

function renderTrace(payload) {
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

export default function EnrichmentPanel({ enrichments }) {
  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Enrichment</p>
          <h3>Context Layers</h3>
        </div>
      </div>

      {enrichments.length === 0 ? (
        <div className="empty-state compact">
          <p>No enrichments have been persisted for this incident.</p>
        </div>
      ) : (
        <div className="enrichment-stack">
          {enrichments.map((enrichment) => (
            <article key={`${enrichment.enrichment_type}-${enrichment.created_at}`} className="enrichment-card">
              <header>
                <strong>{enrichment.enrichment_type.replaceAll("_", " ")}</strong>
                <span>{enrichment.provider}</span>
              </header>
              {enrichment.summary && <p>{enrichment.summary}</p>}
              {enrichment.enrichment_type === "threat_intel"
                ? renderThreatIntel(enrichment.payload)
                : enrichment.enrichment_type === "llm_execution_trace"
                  ? renderTrace(enrichment.payload)
                  : (
                    <pre>{JSON.stringify(enrichment.payload, null, 2)}</pre>
                  )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
