# AI-Powered Security Log Triage & Incident Prioritization Engine

Production-oriented SOC automation platform built around deterministic detection, local-first AI enrichment, and provider-agnostic inference. The system prioritizes incidents, maps MITRE ATT&CK techniques, and generates analyst-ready reports while keeping AI as a bounded enrichment layer rather than the decision-maker.

## Why this project
- Demonstrates security engineering depth beyond a generic AI wrapper.
- Uses deterministic parsing and rule-based detection before any AI enrichment.
- Preserves a local-first architecture while supporting optional hosted inference fallback for constrained hardware and easier demos.
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
│   │   │   ├── analyzer.py
│   │   │   ├── factory.py
│   │   │   ├── ollama_client.py
│   │   │   ├── providers.py
│   │   │   ├── prompts/
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
+---------------------------+      +-------------------------------+
| React SOC Workspace       |----->| FastAPI Incident API          |
| queue | timeline | review |      | uploads | workflow | reports  |
+---------------------------+      +-------------------------------+
                                                 |
                                                 v
                                   +-------------------------------+
                                   | Deterministic Pipeline        |
                                   | parse -> detect -> correlate  |
                                   | -> enrich -> score            |
                                   +-------------------------------+
                                                 |
                            sanitized incident bundle only
                                                 |
                                                 v
                       +-----------------------------------------------+
                       | Provider-Agnostic AI Enrichment Layer         |
                       | local Ollama | hosted API | deterministic-only|
                       | strict JSON validation + per-task fallbacks   |
                       +-----------------------------------------------+
                                                 |
                                                 v
                                   +-------------------------------+
                                   | PostgreSQL / SQLite           |
                                   | incidents, evidence, scores,  |
                                   | enrichments, audit trail      |
                                   +-------------------------------+
```

## Core workflow
1. Upload security log (`auth`, `firewall`, `windows`, `cloud`).
2. Deterministic parser normalizes events to structured JSON.
3. Rule engine flags suspicious events and generates an `IncidentBundle`.
4. Only the sanitized structured bundle is sent to the AI enrichment layer. Raw logs are never sent to any provider.
5. AI enrichment runs in one of three modes:
   - local Ollama
   - hosted API provider
   - deterministic-only mode
6. Every AI task response is schema-validated with Pydantic and allowlisted where required.
7. If AI is unavailable or invalid, deterministic fallback analysis is used automatically.
8. Risk score is computed and final severity is assigned by backend logic.
9. Dashboard displays triage output and MITRE mapping.
10. Incident report can be exported as JSON or Markdown.

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
Invalid JSON or schema mismatches are rejected. The system falls back to deterministic analysis when needed, and can also run in deterministic-only mode by configuration.

## AI enrichment modes
- Recommended default for normal development on constrained hardware:
  `LLM_PROVIDER=deterministic`
- `LLM_PROVIDER=ollama`
  - local-first mode for workstation or lab deployments using Ollama
- `LLM_PROVIDER=hosted`
  - provider-agnostic hosted inference mode for lower-spec machines, demos, or portability
- `LLM_PROVIDER=deterministic`
  - no LLM execution; deterministic fallback enrichment only
- `LLM_PROVIDER=mock`
  - local development and test helper mode that returns valid structured responses without external inference

## Security controls implemented
- Upload extension allowlist and file-size limits.
- MIME-type validation with text-only content sniffing.
- SHA-256 hashing of uploaded artifacts.
- Configurable upload retention metadata for cleanup workflows.
- Bearer-token authentication with role-based access control for `viewer`, `analyst`, and `admin`.
- In-memory rate limiting for read, upload, and review actions.
- Optional deterministic PII redaction mode for uploaded log content.
- Startup configuration validation for auth and redaction settings.
- Safe decoding and malformed-line handling.
- No execution of uploaded content.
- Parser and detection logic are deterministic.
- Prompt-injection resistance by passing only sanitized structured fields to LLM.
- Provider abstraction keeps inference transport swappable without changing scoring or detection logic.
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
curl -H "Authorization: Bearer admin-dev-token-change-me" http://localhost:8000/metrics
curl -H "Authorization: Bearer analyst-dev-token-change-me" http://localhost:8000/api/v1/system/ai-status
```

## Local setup
### Backend
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python -m alembic -c alembic.ini upgrade head
# Set VIEWER_API_TOKEN, ANALYST_API_TOKEN, and ADMIN_API_TOKEN before exposing the app beyond local dev.
# Choose LLM_PROVIDER=ollama, hosted, deterministic, or mock.
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/frontend
npm install
cp .env.example .env
# VITE_API_TOKEN defaults to the analyst demo token in the example env.
npm run dev
```

### Run tests
```bash
cd /Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend
pytest
```

## AI provider configuration
### Local mode (Ollama)
1. Install Ollama locally.
2. Pull model:
```bash
ollama pull llama3.1:8b
```
3. Set `LLM_PROVIDER=ollama`.
4. Start Ollama service and keep default `OLLAMA_BASE_URL=http://localhost:11434`.

### Hosted mode
Use this when you cannot run Ollama locally but still want AI-generated enrichment during a demo. The hosted provider supports OpenAI-compatible chat-completions style responses by default.

Set:
```env
LLM_PROVIDER="hosted"
HOSTED_LLM_BASE_URL="https://your-provider.example"
HOSTED_LLM_ENDPOINT="/v1/chat/completions"
HOSTED_LLM_API_STYLE="openai_chat"
HOSTED_LLM_MODEL="your-model"
HOSTED_LLM_API_KEY="your-api-key"
```

For a custom JSON provider, set `HOSTED_LLM_API_STYLE="generic_json"` and configure `HOSTED_LLM_RESPONSE_FIELD`.

### Deterministic-only mode
Set:
```env
LLM_PROVIDER="deterministic"
```

This mode still parses, detects, correlates, enriches with local threat-intel logic, scores incidents, generates reports, and supports analyst workflow. It skips external AI execution and uses deterministic fallback text for the LLM enrichment fields.

Prompt templates live in:
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/app/llm/prompts/attack_classification.md`
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/app/llm/prompts/mitre_mapping.md`
- `/Users/sjv/Developer/AI-Powered-Security-Log-Triage/backend/app/llm/prompts/analyst_summary.md`

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
- Implemented provider-agnostic AI enrichment with local Ollama, hosted API, mock, and deterministic-only modes, while keeping raw logs out of the model boundary.
- Developed risk-based incident scoring combining rule severity, AI confidence, and asset criticality to drive Low/Medium/High/Critical prioritization.
- Integrated MITRE ATT&CK technique mapping and generated analyst-ready JSON/Markdown incident reports for repeatable investigative handoff.
- Added unit tests for parser correctness, suspicious event detection logic, and LLM output contract validation to support production reliability.
