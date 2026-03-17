const TABS = [
  { id: "triage", label: "Incident Queue" },
  { id: "upload", label: "Upload / Replay" },
  { id: "evaluation", label: "Admin / Evaluation" }
];

export default function WorkspaceTabs({ activeView, onChange }) {
  return (
    <nav className="workspace-tabs" aria-label="Workspace views">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={tab.id === activeView ? "workspace-tab active" : "workspace-tab"}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
}
