# AI-Powered Security Log Triage & Incident Prioritization Engine

Production-oriented SOC automation platform that combines deterministic detection logic with local LLM triage (Ollama + Llama 3.1 8B) to prioritize incidents, map MITRE ATT&CK techniques, and generate analyst-ready reports.

## Why this project
- Demonstrates security engineering depth beyond a generic AI wrapper.
- Uses deterministic parsing and rule-based detection before AI enrichment.
- Enforces strict LLM JSON schema validation for safe downstream use.
- Supports risk-based prioritization using rule weights + confidence + asset criticality.

## Project structure
```text
AI-Powered-Security-Log-Triage/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── database.py
│   │   │   └── security.py
│   │   ├── llm/
│   │   │   ├── ollama_client.py
│   │   │   ├── prompt_template.md
│   │   │   └── validator.py
│   │   ├── models/
│   │   │   ├── db_models.py
│   │   │   └── schemas.py
│   │   ├── parsers/
│   │   │   ├── auth_parser.py
│   │   │   ├── cloud_parser.py
│   │   │   ├── factory.py
│   │   │   ├── firewall_parser.py
│   │   │   └── windows_parser.py
│   │   ├── services/
│   │   │   ├── detection_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── normalization_service.py
│   │   │   ├── report_service.py
│   │   │   └── risk_scoring.py
│   │   ├── utils/
│   │   │   ├── ip_utils.py
│   │   │   └── mitre.py
│   │   └── main.py
│   ├── sample_logs/
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── api.js
│   │   ├── App.jsx
│   │   └── styles.css
│   ├── package.json
│   └── .env.example
├── docs/
│   └── mitre_mapping_reference.md
└── docker-compose.yml
```

## Architecture
```text
                    +-----------------------------+
                    |        React Dashboard      |
                    | Upload | Severity | Reports |
                    +-------------+---------------+
                                  |
                                  v
+--------------------------+   FastAPI API   +------------------------------+
| File Validation Layer    +---------------->+ Incident Orchestration       |
| extension, size, decode  |                 | parse -> detect -> LLM -> DB |
+--------------------------+                 +------------------------------+
          |                                                  |
          v                                                  v
+---------------------------+                    +---------------------------+
| Log Normalization         |                    | Risk Scoring Engine       |
| auth/firewall/windows/    |                    | rule weights + confidence |
| cloud deterministic parse |                    | + asset criticality       |
+---------------------------+                    +---------------------------+
          |                                                  |
          v                                                  v
+---------------------------+                    +---------------------------+
| Rule-based Detection      |                    | Ollama (Local LLM)        |
| failed logins, priv esc,  |------------------->| structured incident bundle |
| suspicious IP, port scan  |  validated JSON    | strict output schema       |
+---------------------------+                    +---------------------------+
          |
          v
+---------------------------+
| PostgreSQL / SQLite       |
| logs, suspicious events,  |
| AI analysis, timestamps   |
+---------------------------+
```

## Core workflow
1. Upload security log (`auth`, `firewall`, `windows`, `cloud`).
2. Deterministic parser normalizes events to structured JSON.
3. Rule engine flags suspicious events and generates an `IncidentBundle`.
4. Only structured bundle is sent to Ollama (no raw logs sent to LLM).
5. LLM response is schema-validated with Pydantic.
6. Risk score is computed and final severity is assigned.
7. Dashboard displays triage output and MITRE mapping.
8. Incident report can be exported as JSON or Markdown.

## LLM output contract (strict)
Expected model JSON:
```json
{
  "severity": "Low | Medium | High | Critical",
  "attack_type": "string",
  "mitre_techniques": ["Txxxx"],
  "confidence_score": 0,
  "analysis_summary": "string",
  "recommended_actions": ["string"]
}
```
Invalid JSON or schema mismatches are rejected. The system falls back to deterministic analysis when needed.

## Security controls implemented
- Upload extension allowlist and file-size limits.
- Safe decoding and malformed-line handling.
- No execution of uploaded content.
- Parser and detection logic are deterministic.
- Prompt-injection resistance by passing only sanitized structured fields to LLM.
- Strict Pydantic validation for LLM output before rendering/storing.
- No hardcoded secrets; environment-driven configuration.

## Observability
- Prometheus-style metrics endpoint available at `/metrics`.
- Structured JSON logging for uploads, pipeline stage timing, task execution, and analyst workflow actions.
- Metrics currently cover:
  - uploads total
  - parse failures
  - detections fired
  - incidents created
  - invalid LLM responses
  - LLM fallback count
  - task runtimes
  - queue depth
  - review counts
  - incident score distribution

Example local verification:
```bash
curl http://localhost:8000/metrics
```

## Local setup
### Backend
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/frontend
npm install
cp .env.example .env
npm run dev
```

### Run tests
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend
pytest
```

## Ollama integration
1. Install Ollama locally.
2. Pull model:
```bash
ollama pull llama3.1:8b
```
3. Start Ollama service and keep default `OLLAMA_BASE_URL=http://localhost:11434`.
4. Backend sends structured bundle to `/api/generate` and validates JSON response.

Prompt template: `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/app/llm/prompt_template.md`

## Docker usage (optional)
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage
docker compose up --build
```
- `frontend`: [http://localhost:5173](http://localhost:5173)
- `backend`: [http://localhost:8000](http://localhost:8000)
- `db`: PostgreSQL on port `5432`

## Sample logs
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/sample_logs/auth.log`
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/sample_logs/firewall.log`
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/sample_logs/windows.log`
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/sample_logs/cloud.log`

## MITRE mapping reference
See `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/docs/mitre_mapping_reference.md`.

## Example response payload
```json
{
  "upload_id": 12,
  "filename": "firewall.log",
  "source_type": "firewall",
  "total_lines": 1200,
  "suspicious_count": 19,
  "severity": "High",
  "risk_score": 78.4,
  "analysis": {
    "severity": "High",
    "attack_type": "Network Reconnaissance and Credential Attack Pattern",
    "mitre_techniques": ["T1046", "T1110"],
    "confidence_score": 84,
    "analysis_summary": "Repeated blocked probes across multiple destination ports with concurrent authentication failures indicate coordinated recon and credential attack behavior.",
    "recommended_actions": [
      "Block source IP ranges at edge firewall and WAF layers.",
      "Enforce MFA and reset targeted account credentials.",
      "Collect host and IAM telemetry for lateral movement validation."
    ]
  }
}
```

## Resume-ready bullets
- Built a full-stack SOC triage platform using FastAPI + React that normalizes heterogeneous security logs and prioritizes incidents with deterministic detection rules.
- Implemented local LLM enrichment (Ollama / Llama 3.1 8B) with strict JSON schema validation, preventing malformed AI output from entering analyst workflows.
- Developed risk-based incident scoring combining rule severity, AI confidence, and asset criticality to drive Low/Medium/High/Critical prioritization.
- Integrated MITRE ATT&CK technique mapping and generated analyst-ready JSON/Markdown incident reports for repeatable investigative handoff.
- Added unit tests for parser correctness, suspicious event detection logic, and LLM output contract validation to support production reliability.
