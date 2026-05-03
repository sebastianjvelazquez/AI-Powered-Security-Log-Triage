import { useCallback, useState } from "react";
import { Play, Upload } from "lucide-react";

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
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback((event) => {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) {
      setFile(dropped);
    }
  }, []);

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
          <h3 style={{ margin: "0 0 5px", fontSize: "0.875rem", fontWeight: 600 }}>Upload Security Log</h3>
          <p className="muted-copy">
            Queue an async analysis job through parsing, enrichment, and scoring.
          </p>

          <div
            className={`dropzone${dragging ? " dragging" : ""}`}
            role="button"
            tabIndex={0}
            aria-label="Drop zone for log files"
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => document.getElementById("log-file-input").click()}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                document.getElementById("log-file-input").click();
              }
            }}
          >
            <div className="dropzone-icon">
              <Upload size={26} aria-hidden="true" />
            </div>
            {file ? (
              <>
                <p className="file-name">{file.name}</p>
                <p>{(file.size / 1024).toFixed(1)} KB</p>
              </>
            ) : (
              <>
                <p>Drop log file here or click to browse</p>
                <p>.log · .txt · .json · .csv</p>
              </>
            )}
          </div>
          <input
            id="log-file-input"
            type="file"
            accept=".log,.txt,.json,.csv"
            style={{ display: "none" }}
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />

          <div style={{ marginBottom: 12 }}>
            <p className="label" style={{ marginBottom: 5 }}>Source Type</p>
            <div className="segmented-control" role="group" aria-label="Source type">
              {SOURCE_TYPES.map((type) => (
                <button
                  key={type}
                  type="button"
                  className={type === sourceType ? "active" : ""}
                  onClick={() => setSourceType(type)}
                  aria-pressed={type === sourceType}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          <button type="submit" className="primary-button" disabled={loading || !file}>
            {loading ? (
              "Submitting…"
            ) : (
              <>
                <Upload size={12} aria-hidden="true" /> Queue Triage Job
              </>
            )}
          </button>
        </form>

        <section className="subpanel replay-panel">
          <h3 style={{ margin: "0 0 5px", fontSize: "0.875rem", fontWeight: 600 }}>Scenario Replay</h3>
          <p className="muted-copy">
            Replay prebuilt attack packs through the same async ingestion path used for uploaded logs.
          </p>

          {replayRun ? (
            <div className="replay-run-card">
              <div
                style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}
              >
                <div>
                  <p className="eyebrow">Active Replay</p>
                  <strong style={{ fontSize: "0.82rem" }}>{replayRun.name}</strong>
                </div>
                <span className="count-pill">{replayRun.jobs.length} jobs</span>
              </div>
              <div className="chip-row" style={{ marginBottom: 8 }}>
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
                    {job.error_message ? (
                      <p style={{ color: "var(--critical)" }}>{job.error_message}</p>
                    ) : null}
                    {job.incident_id ? (
                      <button
                        type="button"
                        className="ghost-button"
                        style={{ marginTop: 6 }}
                        onClick={() => onOpenIncident(job.incident_id)}
                      >
                        Open #{job.incident_id}
                      </button>
                    ) : null}
                  </div>
                ))}
              </div>
              {openableJobs.length > 0 ? (
                <button
                  type="button"
                  className="primary-button"
                  style={{ marginTop: 10 }}
                  onClick={() => onOpenIncident(openableJobs[0].incident_id)}
                >
                  Open First Completed Incident
                </button>
              ) : null}
            </div>
          ) : null}

          <div className="scenario-list">
            {scenarios.map((scenario) => (
              <div key={scenario.scenario_id} className="scenario-card">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <strong style={{ fontSize: "0.82rem" }}>{scenario.name}</strong>
                  <span className="count-pill">{scenario.upload_count} files</span>
                </div>
                <p className="muted-copy">{scenario.description}</p>
                <div className="chip-row">
                  {scenario.tags.map((tag) => (
                    <span key={tag} className="mitre-chip">
                      {tag}
                    </span>
                  ))}
                </div>
                <div
                  style={{ display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between" }}
                >
                  <span style={{ fontSize: "0.68rem", color: "var(--muted)" }}>
                    Expected: {scenario.expected_outcome.expected_min_severity}
                  </span>
                  <button
                    type="button"
                    className="primary-button"
                    disabled={Boolean(replayingScenarioId)}
                    onClick={() => onReplay(scenario.scenario_id)}
                  >
                    <Play size={11} aria-hidden="true" />
                    {replayingScenarioId === scenario.scenario_id ? "Launching…" : "Replay"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
