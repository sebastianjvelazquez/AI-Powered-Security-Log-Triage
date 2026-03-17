import { useMemo, useState } from "react";

const DISPOSITIONS = ["true_positive", "false_positive", "benign", "needs_review", "escalated"];
const STATUSES = ["new", "in_review", "escalated", "closed", "false_positive"];
const SEVERITIES = ["Low", "Medium", "High", "Critical"];

function listFromText(value) {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function AnalystReviewPanel({ incident, loading, onSubmitReview, onStatusUpdate }) {
  const [reviewer, setReviewer] = useState("analyst@example.com");
  const [disposition, setDisposition] = useState("needs_review");
  const [targetStatus, setTargetStatus] = useState("");
  const [overrideSeverity, setOverrideSeverity] = useState("");
  const [notes, setNotes] = useState("");
  const [mitreText, setMitreText] = useState("");
  const [actionsText, setActionsText] = useState("");

  const quickStatuses = useMemo(() => ["in_review", "escalated", "closed", "false_positive"], []);

  if (!incident) {
    return (
      <section className="subpanel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Workflow</p>
            <h3>Analyst Review</h3>
          </div>
        </div>
        <div className="empty-state compact">
          <p>Select an incident to review or override.</p>
        </div>
      </section>
    );
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    await onSubmitReview({
      reviewer,
      disposition,
      notes: notes || null,
      target_status: targetStatus || null,
      override_severity: overrideSeverity || null,
      override_mitre_techniques: mitreText ? listFromText(mitreText) : null,
      override_recommended_actions: actionsText ? listFromText(actionsText) : null
    });
  };

  return (
    <section className="subpanel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Workflow</p>
          <h3>Analyst Review</h3>
        </div>
      </div>

      <div className="quick-actions">
        {quickStatuses.map((status) => (
          <button
            key={status}
            type="button"
            className="ghost-button"
            disabled={loading}
            onClick={() => onStatusUpdate({ reviewer, status, notes: `Quick status update to ${status}.` })}
          >
            Mark {status.replace("_", " ")}
          </button>
        ))}
      </div>

      <form className="review-form" onSubmit={handleSubmit}>
        <label>
          Reviewer
          <input value={reviewer} onChange={(event) => setReviewer(event.target.value)} />
        </label>
        <label>
          Disposition
          <select value={disposition} onChange={(event) => setDisposition(event.target.value)}>
            {DISPOSITIONS.map((option) => (
              <option key={option} value={option}>
                {option.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Target Status
          <select value={targetStatus} onChange={(event) => setTargetStatus(event.target.value)}>
            <option value="">Auto from disposition</option>
            {STATUSES.map((option) => (
              <option key={option} value={option}>
                {option.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Override Severity
          <select value={overrideSeverity} onChange={(event) => setOverrideSeverity(event.target.value)}>
            <option value="">No override</option>
            {SEVERITIES.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <label className="form-span">
          Notes
          <textarea rows="4" value={notes} onChange={(event) => setNotes(event.target.value)} />
        </label>
        <label className="form-span">
          Override MITRE Techniques
          <textarea
            rows="3"
            placeholder={"One MITRE technique per line\nT1110"}
            value={mitreText}
            onChange={(event) => setMitreText(event.target.value)}
          />
        </label>
        <label className="form-span">
          Override Recommended Actions
          <textarea
            rows="4"
            placeholder={"One action per line\nDisable the targeted account."}
            value={actionsText}
            onChange={(event) => setActionsText(event.target.value)}
          />
        </label>

        <button type="submit" className="primary-button" disabled={loading}>
          {loading ? "Saving..." : "Submit Review"}
        </button>
      </form>
    </section>
  );
}
