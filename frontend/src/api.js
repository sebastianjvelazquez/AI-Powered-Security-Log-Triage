const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";
const API_TOKEN = import.meta.env.VITE_API_TOKEN || "analyst-dev-token-change-me";

function buildHeaders(headers = {}) {
  return API_TOKEN
    ? {
        ...headers,
        Authorization: `Bearer ${API_TOKEN}`
      }
    : headers;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: buildHeaders(options.headers)
  });
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

export async function getAiStatus() {
  return requestJson(`${API_BASE}/system/ai-status`);
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

export async function downloadIncidentReport(uploadId, format) {
  const response = await fetch(`${API_BASE}/incidents/${uploadId}/report/${format}`, {
    headers: buildHeaders()
  });
  if (!response.ok) {
    const error = await safeError(response);
    throw new Error(error);
  }

  const blob = await response.blob();
  const extension = format === "json" ? "json" : "md";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `incident-report-${uploadId}.${extension}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function safeError(response) {
  try {
    const body = await response.json();
    return body.detail || "Request failed";
  } catch {
    return "Request failed";
  }
}
