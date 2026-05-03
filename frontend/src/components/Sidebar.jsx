import { useState } from "react";
import { BarChart2, ChevronLeft, ChevronRight, Settings, Shield, Upload, Zap } from "lucide-react";

const NAV_ITEMS = [
  { id: "triage", label: "Incident Queue", Icon: Shield },
  { id: "upload", label: "Upload / Replay", Icon: Upload },
  { id: "evaluation", label: "Evaluation", Icon: BarChart2 }
];

export default function Sidebar({ activeView, onChange, aiStatus }) {
  const [collapsed, setCollapsed] = useState(false);

  const provider = aiStatus?.provider || "unknown";
  const configured = aiStatus?.configured ?? false;
  const modeLabel = aiStatus?.mode_label || "AI Unavailable";

  const dotClass = `sidebar-ai-dot${!configured ? " unconfigured" : provider === "hosted" ? " hosted" : ""}`;

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`} aria-label="Navigation">
      <div className="sidebar-header">
        <Zap className="sidebar-logo" size={18} aria-hidden="true" />
        {!collapsed && <span className="sidebar-title">SOC Platform</span>}
        <button
          type="button"
          className="sidebar-collapse-btn"
          onClick={() => setCollapsed((prev) => !prev)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
        </button>
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {NAV_ITEMS.map(({ id, label, Icon }) => (
          <button
            key={id}
            type="button"
            className={`sidebar-nav-item${activeView === id ? " active" : ""}`}
            onClick={() => onChange(id)}
            title={collapsed ? label : undefined}
            aria-current={activeView === id ? "page" : undefined}
          >
            <Icon className="sidebar-nav-icon" size={17} aria-hidden="true" />
            {!collapsed && <span className="sidebar-nav-label">{label}</span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-footer-item" title={modeLabel}>
          <span className={dotClass} aria-hidden="true" />
          {!collapsed && <span>{modeLabel}</span>}
        </div>
        <div className="sidebar-footer-item" title="Settings">
          <Settings size={15} aria-hidden="true" />
          {!collapsed && <span>Settings</span>}
        </div>
      </div>
    </aside>
  );
}
