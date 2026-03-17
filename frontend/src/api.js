const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const error = await safeError(response);
    throw new Error(error);
  }
  return response.json();
}

export async function uploadLogFile(sourceType, file) {
  const formData = new FormData();
  formData.append("file", file);

  return requestJson(`${API_BASE}/incidents/upload?source_type=${encodeURIComponent(sourceType)}`, {
    method: "POST",
    body: formData
  });
}

export async function getIncidentHistory() {
  return requestJson(`${API_BASE}/incidents/history`);
}

export async function getScenarios() {
  return requestJson(`${API_BASE}/scenarios`);
}

export async function replayScenario(scenarioId) {
  return requestJson(`${API_BASE}/scenarios/${scenarioId}/replay`, {
    method: "POST"
  });
}

export async function getIncidentDetailById(incidentId) {
  return requestJson(`${API_BASE}/incidents/id/${incidentId}`);
}

export async function getJobStatus(jobId) {
  return requestJson(`${API_BASE}/jobs/${jobId}`);
}

export async function submitIncidentReview(incidentId, payload) {
  return requestJson(`${API_BASE}/incidents/${incidentId}/reviews`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
}

export async function updateIncidentStatus(incidentId, payload) {
  return requestJson(`${API_BASE}/incidents/${incidentId}/status`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
}

export function getJsonReportUrl(uploadId) {
  return `${API_BASE}/incidents/${uploadId}/report/json`;
}

export function getMarkdownReportUrl(uploadId) {
  return `${API_BASE}/incidents/${uploadId}/report/markdown`;
}

async function safeError(response) {
  try {
    const body = await response.json();
    return body.detail || "Request failed";
  } catch {
    return "Request failed";
  }
}
