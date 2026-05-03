import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import {
  getAiStatus,
  getIncidentDetailById,
  getIncidentHistory,
  getJobStatus,
  getScenarios,
  replayScenario,
  submitIncidentReview,
  updateIncidentStatus,
  uploadLogFile
} from "./api";
import AiModeBadge from "./components/AiModeBadge";
import AnalystReviewPanel from "./components/AnalystReviewPanel";
import EnrichmentPanel from "./components/EnrichmentPanel";
import EvaluationDashboard from "./components/EvaluationDashboard";
import EventTimeline from "./components/EventTimeline";
import IncidentDetailPanel from "./components/IncidentDetailPanel";
import IncidentQueue from "./components/IncidentQueue";
import JobStatusBanner from "./components/JobStatusBanner";
import RelatedIncidentsPanel from "./components/RelatedIncidentsPanel";
import Sidebar from "./components/Sidebar";
import UploadPanel from "./components/UploadPanel";

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
  const [scenarios, setScenarios] = useState([]);
  const [aiStatus, setAiStatus] = useState(null);
  const [replayRun, setReplayRun] = useState(null);
  const [replayingScenarioId, setReplayingScenarioId] = useState("");
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

  async function loadScenarios() {
    try {
      const data = await getScenarios();
      setScenarios(data);
    } catch (loadError) {
      setError(loadError.message);
      setScenarios([]);
    }
  }

  async function loadAiStatus() {
    try {
      const status = await getAiStatus();
      setAiStatus(status);
    } catch {
      setAiStatus(null);
    }
  }

  useEffect(() => {
    loadHistory();
    loadScenarios();
    loadAiStatus();
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
    if (pollTimeoutRef.current) {
      window.clearTimeout(pollTimeoutRef.current);
    }
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

  const startPollingReplay = (initialRun) => {
    if (pollTimeoutRef.current) {
      window.clearTimeout(pollTimeoutRef.current);
    }

    async function poll() {
      try {
        const updatedJobs = await Promise.all(
          initialRun.jobs.map(async (job) => {
            const status = await getJobStatus(job.job_id);
            return {
              ...job,
              ...status
            };
          })
        );

        const nextRun = {
          ...initialRun,
          jobs: updatedJobs
        };
        setReplayRun(nextRun);

        const completedIncident = updatedJobs.find((job) => job.incident_id);
        if (completedIncident?.incident_id) {
          await loadHistory(completedIncident.incident_id);
        }

        const allFinished = updatedJobs.every((job) => job.status === "completed" || job.status === "failed");
        if (allFinished) {
          setReplayingScenarioId("");
          return;
        }
        pollTimeoutRef.current = window.setTimeout(poll, 1500);
      } catch (pollError) {
        setError(pollError.message);
        setReplayingScenarioId("");
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
      setReplayRun(null);
      setActiveView("upload");
      startPollingJob(job.job_id);
    } catch (uploadError) {
      setError(uploadError.message);
    } finally {
      setSubmittingUpload(false);
    }
  };

  const handleReplay = async (scenarioId) => {
    setReplayingScenarioId(scenarioId);
    setError("");
    try {
      const replay = await replayScenario(scenarioId);
      setReplayRun(replay);
      setJobStatus(null);
      setActiveView("upload");
      startPollingReplay(replay);
    } catch (replayError) {
      setError(replayError.message);
      setReplayingScenarioId("");
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
      <Sidebar activeView={activeView} onChange={setActiveView} aiStatus={aiStatus} />

      <div className="app-content">
        <header className="top-bar">
          <div className="top-bar-breadcrumb">
            <span>SOC Workspace</span>
            <span aria-hidden="true">›</span>
            <span className="current">
              {activeView === "triage"
                ? "Incident Queue"
                : activeView === "upload"
                  ? "Upload / Replay"
                  : "Evaluation"}
            </span>
          </div>

          <div className="top-bar-search">
            <Search size={13} className="top-bar-search-icon" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search incidents…"
              value={filters.search}
              onChange={(event) => setFilter("search", event.target.value)}
              aria-label="Search incidents"
            />
          </div>

          <div className="top-bar-end">
            <div className="top-bar-stat">
              <span>Incidents:</span>
              <strong>{history.length}</strong>
            </div>
            {selectedIncident ? (
              <div className="top-bar-stat">
                <span>Selected:</span>
                <strong>#{selectedIncident.incident_id}</strong>
              </div>
            ) : null}
            <AiModeBadge status={aiStatus} />
          </div>
        </header>

        <main className="app-main">
          {error ? <div className="error-box" role="alert">{error}</div> : null}

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
                      <p>Loading incident detail…</p>
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

          {activeView === "upload" ? (
            <UploadPanel
              onSubmit={handleUpload}
              loading={submittingUpload}
              scenarios={scenarios}
              onReplay={handleReplay}
              replayingScenarioId={replayingScenarioId}
              replayRun={replayRun}
              onOpenIncident={openIncident}
            />
          ) : null}

          {activeView === "evaluation" ? <EvaluationDashboard items={history} /> : null}

          {!loadingHistory && history.length === 0 ? (
            <div className="empty-state tall">
              <p>Queue an upload to start building the incident workspace.</p>
            </div>
          ) : null}
        </main>
      </div>
    </div>
  );
}
