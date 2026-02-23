import { useEffect, useState } from "react";
import { getIncidentHistory, uploadLogFile } from "./api";
import EventsTable from "./components/EventsTable";
import HistoryTable from "./components/HistoryTable";
import IncidentSummary from "./components/IncidentSummary";
import UploadPanel from "./components/UploadPanel";

export default function App() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [incident, setIncident] = useState(null);
  const [history, setHistory] = useState([]);

  async function loadHistory() {
    try {
      const data = await getIncidentHistory();
      setHistory(data);
    } catch {
      setHistory([]);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  const handleSubmit = async (sourceType, file) => {
    setLoading(true);
    setError("");
    try {
      const result = await uploadLogFile(sourceType, file);
      setIncident(result);
      await loadHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header>
        <h1>AI-Powered Security Log Triage</h1>
        <p>Deterministic detection + local LLM prioritization for SOC workflows</p>
      </header>

      {error && <div className="error-box">{error}</div>}

      <div className="grid">
        <UploadPanel onSubmit={handleSubmit} loading={loading} />
        <IncidentSummary incident={incident} />
      </div>

      <EventsTable events={incident?.suspicious_events || []} />
      <HistoryTable items={history} />
    </div>
  );
}
