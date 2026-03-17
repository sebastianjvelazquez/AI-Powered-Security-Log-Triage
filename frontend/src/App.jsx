import { useEffect, useMemo, useRef, useState } from "react";
import {
  getIncidentDetailById,
  getIncidentHistory,
  getJobStatus,
  submitIncidentReview,
  updateIncidentStatus,
  uploadLogFile
} from "./api";
import AnalystReviewPanel from "./components/AnalystReviewPanel";
import EnrichmentPanel from "./components/EnrichmentPanel";
import EvaluationDashboard from "./components/EvaluationDashboard";
import EventTimeline from "./components/EventTimeline";
import IncidentDetailPanel from "./components/IncidentDetailPanel";
import IncidentQueue from "./components/IncidentQueue";
import JobStatusBanner from "./components/JobStatusBanner";
import RelatedIncidentsPanel from "./components/RelatedIncidentsPanel";
import UploadPanel from "./components/UploadPanel";
import WorkspaceTabs from "./components/WorkspaceTabs";

const DEFAULT_FILTERS = {
  search: "",
  severity: "all",
  status: "all",
  source: "all",
  mitre: "all"
};

export default function App() {
  const [activeView, setActiveView] = useState("triage");
  const [history, setHistory] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [jobStatus, setJobStatus] = useState(null);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [submittingUpload, setSubmittingUpload] = useState(false);
  const [submittingReview, setSubmittingReview] = useState(false);
  const [error, setError] = useState("");
  const pollTimeoutRef = useRef(null);

  const mitreOptions = useMemo(
    () =>
      [...new Set(history.flatMap((item) => item.mitre_techniques || []))]
        .filter(Boolean)
        .sort(),
    [history]
  );

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesSearch =
        !filters.search ||
        item.title.toLowerCase().includes(filters.search.toLowerCase()) ||
        (item.filename || "").toLowerCase().includes(filters.search.toLowerCase()) ||
        String(item.incident_id).includes(filters.search);

      const matchesSeverity = filters.severity === "all" || item.severity === filters.severity;
      const matchesStatus = filters.status === "all" || item.status === filters.status;
      const matchesSource = filters.source === "all" || item.source_type === filters.source;
      const matchesMitre =
        filters.mitre === "all" || (item.mitre_techniques || []).includes(filters.mitre);

      return matchesSearch && matchesSeverity && matchesStatus && matchesSource && matchesMitre;
    });
  }, [filters, history]);

  async function loadHistory(preferredIncidentId = null) {
    setLoadingHistory(true);
    try {
      const data = await getIncidentHistory();
      setHistory(data);
      if (preferredIncidentId) {
        setSelectedIncidentId(preferredIncidentId);
      } else if (!selectedIncidentId && data.length > 0) {
        setSelectedIncidentId(data[0].incident_id);
      }
    } catch (loadError) {
      setError(loadError.message);
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  }

  async function loadIncidentDetail(incidentId) {
    if (!incidentId) {
      setSelectedIncident(null);
      return;
    }
    setLoadingDetail(true);
    try {
      const detail = await getIncidentDetailById(incidentId);
      setSelectedIncident(detail);
    } catch (loadError) {
      setError(loadError.message);
      setSelectedIncident(null);
    } finally {
      setLoadingDetail(false);
    }
  }

  useEffect(() => {
    loadHistory();
    return () => {
      if (pollTimeoutRef.current) {
        window.clearTimeout(pollTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const setFilter = (key, value) => {
    setFilters((current) => ({
      ...current,
      [key]: value
    }));
  };

  const openIncident = async (incidentId) => {
    setActiveView("triage");
    setSelectedIncidentId(incidentId);
    await loadIncidentDetail(incidentId);
  };

  const startPollingJob = (jobId) => {
    async function poll() {
      try {
        const status = await getJobStatus(jobId);
        setJobStatus(status);
        if (status.status === "completed" || status.status === "failed") {
          if (status.incident_id) {
            await loadHistory(status.incident_id);
            await openIncident(status.incident_id);
          } else {
            await loadHistory();
          }
          return;
        }
        pollTimeoutRef.current = window.setTimeout(poll, 1500);
      } catch (pollError) {
        setError(pollError.message);
      }
    }

    poll();
  };

  const handleUpload = async (sourceType, file) => {
    setSubmittingUpload(true);
    setError("");
    try {
      if (pollTimeoutRef.current) {
        window.clearTimeout(pollTimeoutRef.current);
      }
      const job = await uploadLogFile(sourceType, file);
      setJobStatus(job);
      setActiveView("upload");
      startPollingJob(job.job_id);
    } catch (uploadError) {
      setError(uploadError.message);
    } finally {
      setSubmittingUpload(false);
    }
  };

  const handleReviewSubmit = async (payload) => {
    if (!selectedIncidentId) {
      return;
    }
    setSubmittingReview(true);
    setError("");
    try {
      const updated = await submitIncidentReview(selectedIncidentId, payload);
      setSelectedIncident(updated);
      await loadHistory(selectedIncidentId);
    } catch (reviewError) {
      setError(reviewError.message);
    } finally {
      setSubmittingReview(false);
    }
  };

  const handleStatusUpdate = async (payload) => {
    if (!selectedIncidentId) {
      return;
    }
    setSubmittingReview(true);
    setError("");
    try {
      const updated = await updateIncidentStatus(selectedIncidentId, payload);
      setSelectedIncident(updated);
      await loadHistory(selectedIncidentId);
    } catch (reviewError) {
      setError(reviewError.message);
    } finally {
      setSubmittingReview(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">SOC Workspace</p>
          <h1>AI-Powered Security Log Triage</h1>
          <p className="hero-copy">
            Incident-centric analyst workflow for async ingestion, explainable scoring, enrichment, and review.
          </p>
        </div>
        <div className="hero-metrics">
          <div>
            <span className="label">Queued Incidents</span>
            <strong>{history.length}</strong>
          </div>
          <div>
            <span className="label">Selected</span>
            <strong>{selectedIncident ? `#${selectedIncident.incident_id}` : "None"}</strong>
          </div>
        </div>
      </header>

      <WorkspaceTabs activeView={activeView} onChange={setActiveView} />

      {error ? <div className="error-box">{error}</div> : null}

      <JobStatusBanner jobStatus={jobStatus} onOpenIncident={openIncident} />

      {activeView === "triage" ? (
        <div className="workspace-layout">
          <IncidentQueue
            items={filteredHistory}
            filters={filters}
            mitreOptions={mitreOptions}
            selectedIncidentId={selectedIncidentId}
            onFilterChange={setFilter}
            onSelect={setSelectedIncidentId}
          />

          <div className="workspace-center">
            <IncidentDetailPanel incident={selectedIncident} />
            <AnalystReviewPanel
              incident={selectedIncident}
              loading={submittingReview}
              onSubmitReview={handleReviewSubmit}
              onStatusUpdate={handleStatusUpdate}
            />
          </div>

          <div className="workspace-right">
            {loadingDetail ? (
              <section className="subpanel">
                <div className="empty-state compact">
                  <p>Loading incident detail...</p>
                </div>
              </section>
            ) : null}
            <EventTimeline events={selectedIncident?.suspicious_events || []} />
            <EnrichmentPanel enrichments={selectedIncident?.enrichments || []} />
            <RelatedIncidentsPanel
              currentIncident={selectedIncident}
              history={history}
              onSelectIncident={setSelectedIncidentId}
            />
          </div>
        </div>
      ) : null}

      {activeView === "upload" ? <UploadPanel onSubmit={handleUpload} loading={submittingUpload} /> : null}

      {activeView === "evaluation" ? <EvaluationDashboard items={history} /> : null}

      {!loadingHistory && history.length === 0 ? (
        <div className="empty-state tall">
          <p>Queue an upload to start building the incident workspace.</p>
        </div>
      ) : null}
    </div>
  );
}
