import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle, Loader, XCircle } from "lucide-react";

export default function JobStatusBanner({ jobStatus, onOpenIncident }) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    setVisible(true);
    if (jobStatus?.status === "completed") {
      const timer = setTimeout(() => setVisible(false), 5000);
      return () => clearTimeout(timer);
    }
  }, [jobStatus?.job_id, jobStatus?.status]);

  if (!jobStatus || !visible) {
    return null;
  }

  const isRunning = jobStatus.status === "running" || jobStatus.status === "queued";

  const Icon =
    jobStatus.status === "completed"
      ? CheckCircle
      : jobStatus.status === "failed"
        ? XCircle
        : jobStatus.status === "running"
          ? Loader
          : AlertCircle;

  const iconColor =
    jobStatus.status === "completed"
      ? "var(--low)"
      : jobStatus.status === "failed"
        ? "var(--critical)"
        : "var(--medium)";

  return (
    <div className={`job-banner job-${jobStatus.status}`} role="status">
      <Icon
        className="job-banner-icon"
        size={15}
        style={{
          color: iconColor,
          animation: jobStatus.status === "running" ? "spin 1.2s linear infinite" : undefined
        }}
        aria-hidden="true"
      />
      <div className="job-banner-info">
        <h4>
          Job {jobStatus.job_id} · {jobStatus.status}
        </h4>
        <p>
          Stage: {jobStatus.current_stage}
          {jobStatus.error_message ? ` · ${jobStatus.error_message}` : ""}
        </p>
        {isRunning ? (
          <div className="job-progress-bar" aria-hidden="true">
            <div className="job-progress-fill" />
          </div>
        ) : null}
      </div>
      {jobStatus.incident_id ? (
        <button type="button" className="primary-button" onClick={() => onOpenIncident(jobStatus.incident_id)}>
          Open Incident
        </button>
      ) : null}
    </div>
  );
}
