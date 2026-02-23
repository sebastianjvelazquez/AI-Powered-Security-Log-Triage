const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export async function uploadLogFile(sourceType, file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE}/incidents/upload?source_type=${encodeURIComponent(sourceType)}`, {
    method: "POST",
    body: formData
  });

  if (!response.ok) {
    const err = await safeError(response);
    throw new Error(err);
  }

  return response.json();
}

export async function getIncidentHistory() {
  const response = await fetch(`${API_BASE}/incidents/history`);
  if (!response.ok) {
    throw new Error("Unable to load incident history");
  }
  return response.json();
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
    return body.detail || "Upload failed";
  } catch {
    return "Upload failed";
  }
}
