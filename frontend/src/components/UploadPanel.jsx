import { useState } from "react";

const SOURCE_TYPES = ["auth", "firewall", "windows", "cloud"];

function statusCounts(jobs) {
  return jobs.reduce((accumulator, job) => {
    accumulator[job.status] = (accumulator[job.status] || 0) + 1;
    return accumulator;
  }, {});
}

export default function UploadPanel({
  onSubmit,
  loading,
  scenarios,
  onReplay,
  replayingScenarioId,
  replayRun,
  onOpenIncident
}) {
  const [sourceType, setSourceType] = useState("auth");
  const [file, setFile] = useState(null);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!file) {
      return;
    }
    onSubmit(sourceType, file);
  };

  const counts = replayRun ? statusCounts(replayRun.jobs) : {};
  const openableJobs = replayRun ? replayRun.jobs.filter((job) => job.incident_id) : [];

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
            Replay prebuilt attack packs through the same async ingestion path used for uploaded logs.
          </p>

          {replayRun ? (
            <div className="replay-run-card">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">Active Replay</p>
                  <h4>{replayRun.name}</h4>
                </div>
                <span className="count-pill">{replayRun.jobs.length} jobs</span>
              </div>
              <div className="chip-row">
                {Object.entries(counts).map(([status, count]) => (
                  <span key={status} className={`status-chip status-${status}`}>
                    {status}: {count}
                  </span>
                ))}
              </div>
              <div className="mini-list">
                {replayRun.jobs.map((job) => (
                  <div key={job.job_id} className="mini-card">
                    <strong>{job.filename}</strong>
                    <p>
                      {job.source_type} · {job.status} · {job.current_stage}
                    </p>
                    {job.error_message ? <p>{job.error_message}</p> : null}
                    {job.incident_id ? (
                      <button type="button" className="ghost-button" onClick={() => onOpenIncident(job.incident_id)}>
                        Open Incident #{job.incident_id}
                      </button>
                    ) : null}
                  </div>
                ))}
              </div>
              {openableJobs.length > 0 ? (
                <button
                  type="button"
                  className="primary-button"
                  onClick={() => onOpenIncident(openableJobs[0].incident_id)}
                >
                  Open First Completed Incident
                </button>
              ) : null}
            </div>
          ) : null}

          <div className="scenario-list">
            {scenarios.map((scenario) => (
              <div key={scenario.scenario_id} className="mini-card scenario-card">
                <strong>{scenario.name}</strong>
                <p>{scenario.description}</p>
                <div className="chip-row">
                  {scenario.tags.map((tag) => (
                    <span key={tag} className="mitre-chip">
                      {tag}
                    </span>
                  ))}
                </div>
                <p>
                  Uploads: {scenario.upload_count} · Sources: {scenario.source_types.join(", ")}
                </p>
                <p>
                  Expected: {scenario.expected_outcome.expected_min_severity} · Rules{" "}
                  {scenario.expected_outcome.expected_rule_hits.join(", ") || "none"}
                </p>
                <button
                  type="button"
                  className="primary-button"
                  disabled={Boolean(replayingScenarioId)}
                  onClick={() => onReplay(scenario.scenario_id)}
                >
                  {replayingScenarioId === scenario.scenario_id ? "Launching..." : "Replay Scenario"}
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
