# بينة (Baunah) — Industrial / Forensic IDS Dashboard

Arabic-first web application for uploading network or OT evidence (CSV), running **XGBoost** classification, enriching results with **Google Gemini**, and presenting **MITRE ATT&CK (ICS-aligned)** timelines, custody chain, suspicious findings, recommendations, and a final Markdown report.

---

## Technologies

| Layer | Technology | Role |
|--------|------------|------|
| **Frontend** | React 19, Vite 8 | SPA UI, file upload, tabs, animations |
| **Frontend** | Framer Motion | Page/tab transitions and micro-interactions |
| **Frontend** | Lucide React | Icons |
| **Frontend** | react-markdown + remark-gfm | Render Gemini/report text as Markdown (headings, lists, tables, code) |
| **Backend** | Python 3, FastAPI, Uvicorn | REST API (`/analyze`, `/chat-recommendations`, health/setup) |
| **Backend** | pandas | CSV ingest, cleaning, feature alignment |
| **ML** | XGBoost, scikit-learn, joblib | Load `best_xgboost_model.json`, `robust_scaler.joblib`, `feature_columns.json` |
| **AI** | Gemini API (via `requests`) | Narratives, MITRE map, suspicious findings, recommendations, report (optional) |
| **Standards** | MITRE ATT&CK for ICS | Tactic ordering, technique mapping, attack sequence UI |

Optional: `pypdf` in backend requirements for PDF-related utilities if used elsewhere.

### Full stack (AI, frontend, backend, API)

**AI & machine learning**

- **XGBoost** — Gradient-boosted trees; loaded from `best_xgboost_model.json` for per-row (or per-flow) malicious/benign scoring and probabilities.
- **scikit-learn** — `RobustScaler` (and related utilities such as `train_test_split` where used) for feature scaling consistent with training; scaler persisted as `robust_scaler.joblib`.
- **joblib** — Load/save the scaler and other serialized artifacts.
- **Google Gemini** — Not a Python package: the backend calls the **Generative Language API** over **HTTPS** with `requests` (`POST` to `generativelanguage.googleapis.com`, model e.g. `gemini-2.5-flash:generateContent`). Used to enrich narratives, `mitre_attack_map`, suspicious findings, recommendations, and Markdown/final report when `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) is set.
- **Heuristics & rules** — Server-side logic (pandas, custom Python) for timelines, MITRE stage normalization, custody chain, and fallbacks when Gemini is off or fails.
- **MITRE ATT&CK (ICS)** — Reference data and mappings (plus optional `mitre_attack_guide.pdf` text for prompts), not a separate runtime library.

**Frontend**

- **React 19** — UI components, state, and tabbed workflow (RTL Arabic UI).
- **react-dom** — DOM rendering.
- **Vite** — Dev server, HMR, production bundling (`npm run dev` / `npm run build`).
- **@vitejs/plugin-react** — React/SWC integration for Vite.
- **Framer Motion** — Animations for panels, tabs, and transitions.
- **lucide-react** — Icon set.
- **react-markdown** — Render Markdown returned by the API (reports, chat, findings).
- **remark-gfm** — GitHub-flavored Markdown (tables, task lists, strikethrough) for `react-markdown`.
- **ESLint** (+ React hooks / refresh plugins, `@eslint/js`, `globals`) — Linting in development.

**Backend (Python)**

- **Python 3** — Runtime for the analysis service.
- **FastAPI** — Web framework: route definitions, request validation, `UploadFile` for CSV uploads, JSON responses.
- **Uvicorn** — ASGI server used to run the FastAPI app (`uvicorn backend.app:app`).
- **Starlette** (via FastAPI) — Underlying ASGI app; **CORSMiddleware** enabled for browser access.
- **Pydantic** — Request/response models and field validation (`BaseModel`, `Field`).
- **pandas** — CSV read/write, column alignment, missing-value handling, feature frames for inference.
- **python-multipart** — Parsing `multipart/form-data` for file uploads.
- **python-dotenv** — Load `backend/.env` for secrets (e.g. Gemini key).
- **requests** — HTTP client for Gemini API calls.
- **pypdf** — Listed in requirements for PDF text extraction (e.g. MITRE guide) when used.
- **Standard library** — `hashlib`, `json`, `re`, `concurrent.futures` (`ThreadPoolExecutor`), `datetime`, `pathlib`, etc., for hashing, orchestration, and utilities.

**API surface (REST)**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/analyze` | Upload evidence file; returns JSON with `summary`, `timeline`, `mitre_attack_map`, `suspicious_findings`, `recommendations`, `final_report`, `markdown_report`, `custody_chain`, hashes, etc. |
| `POST` | `/chat-recommendations` | Body: prior recommendations + user question + optional analysis context; returns assistant reply (Gemini-backed when configured). |
| `GET` | `/health` | Liveness / basic health. |
| `GET` | `/setup-status` | Model files / Gemini availability hints for diagnostics. |

**Frontend ↔ API wiring**

- In development, **Vite** proxies **`/api`** → `http://localhost:8000` and strips the `/api` prefix so the browser can call `/api/analyze` while the FastAPI app exposes `/analyze`.
- Optional env **`VITE_IDS_API_URL`** — Base URL for the IDS API if you do not use the proxy (e.g. full URL to another host/port).

---

## High-level architecture

1. **Browser** → uploads CSV to **Vite dev server** (proxies `/api` → FastAPI) or calls API URL from `VITE_IDS_API_URL`.
2. **FastAPI** `/analyze` loads the model, scores rows, builds summary, timeline, custody chain, MITRE map (heuristic + optional Gemini normalization), suspicious findings, recommendations, `markdown_report`, `final_report`.
3. **React** renders tabs: file hash, attack sequence (`MitreAttackMap`), suspicious logs, urgent recommendations + Gemini chat, custody chain, final report (Markdown preview + download).

---

## Steps applied in this application (feature / pipeline)

### A. Evidence ingestion

1. User selects or drags a file (CSV, LOG, PCAP, TXT, etc. as configured).
2. Frontend sends **multipart** `POST /analyze` with the file.
3. Backend reads CSV with **pandas**, coerces types, fills missing values (tracked in summary), aligns columns to `feature_columns.json`.

### B. Machine learning detection

4. Features are scaled with the persisted **RobustScaler**.
5. **XGBoost** predicts malicious vs benign (or probabilities); summary includes malicious rate, counts, high-risk rows, `inference_mode` (model vs heuristic fallback).

### C. Timeline & MITRE

6. **Timeline** is built from top malicious rows and/or explicit MITRE columns in the CSV (e.g. training datasets with `mitre_id`, `mitre_tactic`), when present.
7. **MITRE attack map** stages are normalized: ICS tactic order, one primary technique per stage, deduplication, Arabic/English tactic labels, optional Gemini narrative and `_meta` (enrichment source, fingerprint).

### D. Gemini enrichment (optional)

8. If `GEMINI_API_KEY` is set, a structured prompt sends row samples + summary; response fills or refines narrative, `mitre_attack_map`, `suspicious_findings`, `recommendations`, `final_report`, `markdown_report`. Server-side guards reduce generic or duplicate output and merge with rule-based fallbacks.

### E. Custody chain

9. **Custody chain** steps (upload, hash, analysis, report) are generated on the server with UTC timestamps; the UI can synthesize a minimal chain if the field is missing (older API).

### F. Investigator UI

10. **Suspicious findings** cards deduplicate and merge similar rows; evidence bullets avoid repeating raw metrics already in the narrative.
11. **Recommendations** combine Gemini with **dynamic** context-based suggestions (USB/SCADA patterns, MITRE techniques, malicious rate).
12. **Final report** prefers a non-generic, evidence-grounded summary; full **Markdown** report is shown with **react-markdown** and downloadable as `.md`.
13. **Chat** (`/chat-recommendations`) continues Q&A with context from the last analysis; assistant replies rendered as Markdown.
14. **Visual dashboard** (sidebar “عرض مرئي”) shows a compact KPI view: malicious-rate ring, file stats, MITRE stage count, timeline excerpt.
15. **Branding / UX**: RTL layout, dark theme (`#060c12` sidebar, accent `#03512c` / `#6eb870`), logo asset `lastloggoooo.jpg`, sidebar actions (verify + visual).

---

## Repository layout (important paths)

- `src/App.jsx` — Main UI, analysis state, tabs, custody, report, chat, visual overlay.
- `src/components/MitreAttackMap.jsx` — Interactive MITRE flow.
- `src/components/MarkdownBlock.jsx` — Shared Markdown renderer.
- `backend/app.py` — FastAPI app, model load, `/analyze`, Gemini, MITRE normalization.
- `backend/model/` — Exported XGBoost + scaler + feature list (see `backend/EXPORT_FROM_NOTEBOOK.md`).
- `sample-data/` — Example CSVs for testing.

---

## Setup

### 1) Model artifacts

Follow **`backend/EXPORT_FROM_NOTEBOOK.md`** after training in the notebook. Required under `backend/model/`:

- `best_xgboost_model.json`
- `robust_scaler.joblib`
- `feature_columns.json`

### 2) Backend

```bash
pip install -r backend/requirements.txt
```

Optional: `backend/.env` or environment:

```bash
GEMINI_API_KEY=your_key_here
```

Run:

```bash
uvicorn backend.app:app --reload --port 8000
```

### 3) Frontend

```bash
npm install
npm run dev
```

Optional:

```bash
VITE_IDS_API_URL=http://localhost:8000
```

(Vite proxy maps `/api` to the backend when configured in `vite.config.js`.)

### 4) Documentation PDF

From the project root (after `pip install fpdf2`):

```bash
python scripts/generate_baunah_pdf.py
```

Output: **`docs/BAUNAH_APPLICATION_GUIDE.pdf`** (English technical summary; mirrors this README).

---

## API summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze` | POST (file) | Full analysis JSON + markdown fields |
| `/chat-recommendations` | POST | Gemini chat with session context |
| `/health` / `/setup-status` | GET | Service and model/Gemini status |

---

## License / version

Project version shown in the UI sidebar (e.g. 1.0.0). Add license file if you distribute publicly.
