export default function JobStatusBanner({ jobStatus, onOpenIncident }) {
  if (!jobStatus) {
    return null;
  }

  return (
    <section className={`job-banner job-${jobStatus.status}`}>
      <div>
        <p className="eyebrow">Async Pipeline</p>
        <h3>
          Job {jobStatus.job_id} · {jobStatus.status}
        </h3>
        <p>
          Stage: {jobStatus.current_stage}
          {jobStatus.error_message ? ` · ${jobStatus.error_message}` : ""}
        </p>
      </div>
      {jobStatus.incident_id ? (
        <button type="button" className="primary-button" onClick={() => onOpenIncident(jobStatus.incident_id)}>
          Open Incident
        </button>
      ) : null}
    </section>
  );
}
