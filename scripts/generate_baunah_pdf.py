"""
Generate docs/BAUNAH_APPLICATION_GUIDE.pdf (ASCII-only body for built-in fonts).
Run from repository root: python scripts/generate_baunah_pdf.py
Requires: pip install fpdf2
"""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "BAUNAH_APPLICATION_GUIDE.pdf"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    col_w = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "Baunah (Bayyinah) IDS / Forensic Dashboard", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 11)
    sections: list[tuple[str, str]] = [
        (
            "Purpose",
            "Arabic-first web app to upload evidence CSVs, run XGBoost classification, optionally "
            "enrich with Google Gemini, and show MITRE ATT&CK (ICS-style) attack sequence, custody "
            "chain, suspicious findings, recommendations, Markdown report, and a visual summary panel.",
        ),
        (
            "Technologies - Frontend",
            "React 19, Vite 8, Framer Motion, Lucide React, react-markdown + remark-gfm (Gemini and "
            "report rendering). RTL layout and dark UI.",
        ),
        (
            "Technologies - Backend",
            "Python, FastAPI, Uvicorn, pandas, XGBoost, scikit-learn, joblib, requests, "
            "python-multipart, python-dotenv. Optional Gemini via API key.",
        ),
        (
            "Step 1 - Evidence upload",
            "User selects or drags a file. Browser POSTs multipart form to /analyze.",
        ),
        (
            "Step 2 - CSV processing",
            "pandas loads CSV, handles missing values, aligns columns to feature_columns.json.",
        ),
        (
            "Step 3 - ML inference",
            "RobustScaler + XGBoost model predict probabilities; summary: malicious rate, counts, "
            "high-risk flows, inference_mode.",
        ),
        (
            "Step 4 - Timeline",
            "Timeline from malicious rows and/or explicit MITRE columns in CSV when present.",
        ),
        (
            "Step 5 - MITRE map",
            "Stages normalized: ICS tactic order, one technique per stage, dedupe, Arabic/English "
            "labels; optional Gemini narrative and _meta fingerprint.",
        ),
        (
            "Step 6 - Gemini (optional)",
            "If GEMINI_API_KEY set: enrich narrative, mitre_attack_map, suspicious_findings, "
            "recommendations, final_report, markdown_report; server merges with heuristics.",
        ),
        (
            "Step 7 - Custody chain",
            "Server builds chain with UTC timestamps; client fallback if field missing.",
        ),
        (
            "Step 8 - Suspicious findings",
            "Cards deduplicated; evidence bullets cleaned from redundant metrics.",
        ),
        (
            "Step 9 - Recommendations",
            "Dynamic rules + Gemini; context from techniques and file patterns.",
        ),
        (
            "Step 10 - Report",
            "final_report and markdown_report; UI renders Markdown; download as .md file.",
        ),
        (
            "Step 11 - Chat",
            "POST /chat-recommendations with session context; assistant reply as Markdown.",
        ),
        (
            "Step 12 - Visual panel",
            "Sidebar button opens overlay: KPI ring, file stats, MITRE stage count, timeline excerpt.",
        ),
        (
            "Setup - Backend",
            "pip install -r backend/requirements.txt; export GEMINI_API_KEY; "
            "uvicorn backend.app:app --reload --port 8000",
        ),
        (
            "Setup - Frontend",
            "npm install; npm run dev; optional VITE_IDS_API_URL=http://localhost:8000",
        ),
        (
            "Model files",
            "Place under backend/model/: best_xgboost_model.json, robust_scaler.joblib, "
            "feature_columns.json (see backend/EXPORT_FROM_NOTEBOOK.md).",
        ),
    ]

    for title, body in sections:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(col_w, 5, body, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(
        col_w,
        5,
        "Generated for Baunah project. Full detail: README.md in repository root.",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.output(str(OUT))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
