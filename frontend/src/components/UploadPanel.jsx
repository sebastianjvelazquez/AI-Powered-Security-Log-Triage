import { useState } from "react";

const SOURCE_TYPES = ["auth", "firewall", "windows", "cloud"];

export default function UploadPanel({ onSubmit, loading }) {
  const [sourceType, setSourceType] = useState("auth");
  const [file, setFile] = useState(null);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!file) {
      return;
    }
    onSubmit(sourceType, file);
  };

  return (
    <form className="panel upload-panel" onSubmit={handleSubmit}>
      <h2>Upload Security Log</h2>
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
        <input type="file" accept=".log,.txt,.json,.csv" onChange={(event) => setFile(event.target.files?.[0] || null)} />
      </label>

      <button type="submit" disabled={loading || !file}>
        {loading ? "Analyzing..." : "Run Triage"}
      </button>
    </form>
  );
}
