import { useState } from "react";

const SOURCE_TYPES = ["auth", "firewall", "windows", "cloud"];

export default function UploadPanel({ onSubmit, loading }) {
  const [sourceType, setSourceType] = useState("auth");
  const [file, setFile] = useState(null);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!file) {
      return;
    }
    onSubmit(sourceType, file);
  };

  return (
    <section className="workspace-panel upload-view">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Ingestion</p>
          <h2>Upload / Replay</h2>
        </div>
      </div>

      <div className="upload-grid">
        <form className="subpanel upload-panel" onSubmit={handleSubmit}>
          <h3>Upload Security Log</h3>
          <p className="muted-copy">Queue an async analysis job and follow it through parsing, enrichment, and scoring.</p>

          <label>
            Source Type
            <select value={sourceType} onChange={(event) => setSourceType(event.target.value)}>
              {SOURCE_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </label>

          <label>
            Log File
            <input
              type="file"
              accept=".log,.txt,.json,.csv"
              onChange={(event) => setFile(event.target.files?.[0] || null)}
            />
          </label>

          <button type="submit" className="primary-button" disabled={loading || !file}>
            {loading ? "Submitting..." : "Queue Triage Job"}
          </button>
        </form>

        <section className="subpanel replay-panel">
          <h3>Scenario Replay</h3>
          <p className="muted-copy">
            Replayable attack packs land in Phase 9. This workspace is reserved for password spray, recon chains,
            privilege escalation, and noisy benign admin baselines.
          </p>
          <div className="scenario-list">
            {[
              "Password spray against exposed VPN",
              "Recon to auth abuse sequence",
              "Privilege escalation follow-on",
              "Suspicious cloud login chain"
            ].map((scenario) => (
              <div key={scenario} className="mini-card disabled-card">
                <strong>{scenario}</strong>
                <p>Replay controls arrive in the scenario service phase.</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
