import hashlib
import json
import os
import re
import secrets
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import requests
import xgboost as xgb
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "best_xgboost_model.json"
SCALER_PATH = MODEL_DIR / "robust_scaler.joblib"
FEATURES_PATH = MODEL_DIR / "feature_columns.json"
MITRE_GUIDE_PDF = BASE_DIR.parent / "src" / "assets" / "mitre_attack_guide.pdf"
_MITRE_GUIDE_TEXT_CACHE: str | None = None

try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except Exception:
    pass


def _gemini_api_key() -> str | None:
    """Prefer GEMINI_API_KEY; accept GOOGLE_API_KEY for Google AI Studio."""
    return (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip() or None


GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)

app = FastAPI(title="Baunah IDS API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRecommendationRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    analysis_summary: dict[str, Any] | None = None
    recommendations: list[str] | None = None
    timeline: list[dict[str, Any]] | None = None
    suspicious_findings: list[dict[str, Any]] | None = None
    mitre_attack_map: dict[str, Any] | None = None
    history: list[dict[str, str]] | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """OAuth2-style payload — replace access_token with a signed JWT when hardening."""

    access_token: str
    token_type: str = "bearer"
    username: str


# Static demo account — replace with DB + password hashes + JWT (python-jose, passlib).
_AUTH_DEMO_USERNAME = "1111"
_AUTH_DEMO_PASSWORD = "1111"


@app.post("/auth/login", response_model=LoginResponse)
def auth_login(payload: LoginRequest) -> LoginResponse:
    if (
        payload.username != _AUTH_DEMO_USERNAME
        or payload.password != _AUTH_DEMO_PASSWORD
    ):
        raise HTTPException(
            status_code=401,
            detail="اسم المستخدم أو كلمة المرور غير صحيحة.",
        )
    token = secrets.token_urlsafe(48)
    return LoginResponse(access_token=token, username=payload.username)


def _local_investigator_answer(question: str) -> str:
    q = question.strip().lower()
    if "كلمة المرور" in q or "password" in q:
        return (
            "لإعادة تعيين كلمة المرور بشكل آمن:\n"
            "1) عطّل الحساب مؤقتاً إذا كان مشبوهاً.\n"
            "2) أعد التعيين من لوحة الهوية المركزية مع توثيق السبب.\n"
            "3) فعّل MFA وألغِ كل الجلسات النشطة.\n"
            "4) راجع سجلات الدخول قبل وبعد التغيير للتأكد من عدم وجود استخدام غير مصرح.\n"
            "5) إذا كان الحساب عالي الصلاحية، بدّل مفاتيح/رموز الوصول المرتبطة به."
        )
    if "zero" in q or "زيرو" in q or "zero-day" in q:
        return (
            "لا يمكن الجزم بأنه Zero-day من نتيجة النموذج وحدها. "
            "يلزم جمع أدلة إضافية: سلوك العملية، IOC، sandbox، وسجلات EDR/SIEM "
            "قبل اعتماد التصنيف النهائي."
        )
    if "malware" in q or "برمجية" in q or "عائلة" in q:
        return (
            "لتحديد عائلة البرمجية الخبيثة بدقة، طابق المؤشرات التالية: "
            "سلاسل C2، التوقيع السلوكي، التجزئة، القواعد YARA، ونمط الانتشار. "
            "نتيجة IDS وحدها مؤشر أولي وليست تصنيف عائلة نهائي."
        )
    return (
        "أفهم سؤالك. للحصول على إجابة أدق للمحقق، أرسل التفاصيل التالية: "
        "النطاق الزمني، الجهاز/الحساب المتأثر، وأي سلوك أو سجل محدد تريد تحليله."
    )


def _read_feature_columns() -> list[str] | None:
    if FEATURES_PATH.exists():
        return json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
    return None


def _calculate_hashes(file_bytes: bytes) -> dict[str, str]:
    return {
        "SHA256": hashlib.sha256(file_bytes).hexdigest(),
        "SHA3_256": hashlib.sha3_256(file_bytes).hexdigest(),
        "BLAKE2B": hashlib.blake2b(file_bytes).hexdigest(),
        "SHA1": hashlib.sha1(file_bytes).hexdigest(),
        "MD5": hashlib.md5(file_bytes).hexdigest(),
    }


def _load_model() -> xgb.XGBClassifier:
    if not MODEL_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail="Missing best_xgboost_model.json. Export artifacts from notebook first.",
        )
    model = xgb.XGBClassifier()
    model.load_model(str(MODEL_PATH))
    return model


def _load_scaler():
    if not SCALER_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail="Missing robust_scaler.joblib. Export artifacts from notebook first.",
        )
    return joblib.load(SCALER_PATH)


def _setup_status() -> dict[str, Any]:
    missing = []
    if not MODEL_PATH.exists():
        missing.append("best_xgboost_model.json")
    if not SCALER_PATH.exists():
        missing.append("robust_scaler.joblib")
    has_feature_list = FEATURES_PATH.exists()
    if not has_feature_list and SCALER_PATH.exists():
        try:
            scaler = joblib.load(SCALER_PATH)
            if hasattr(scaler, "feature_names_in_"):
                has_feature_list = True
        except Exception:
            has_feature_list = False

    if not has_feature_list and MODEL_PATH.exists():
        try:
            model = xgb.XGBClassifier()
            model.load_model(str(MODEL_PATH))
            booster_names = model.get_booster().feature_names or []
            if len(booster_names) > 0:
                has_feature_list = True
        except Exception:
            has_feature_list = False

    if not has_feature_list:
        missing.append("feature_columns.json (or scaler/model feature names)")
    return {
        "ready": len(missing) == 0,
        "missing_artifacts": missing,
        "gemini_enabled": bool(_gemini_api_key()),
    }


def _bootstrap_artifacts_from_dataframe(df: pd.DataFrame) -> dict[str, Any]:
    if "Label" not in df.columns:
        raise HTTPException(
            status_code=500,
            detail=(
                "Model artifacts are missing and bootstrap training requires a CSV "
                "with 'Label' column."
            ),
        )

    work_df = df.copy()
    work_df = work_df.dropna(subset=["Label"])
    if work_df.empty:
        raise HTTPException(status_code=500, detail="Bootstrap failed: empty labeled data.")

    y = work_df["Label"].astype(str).str.lower().apply(lambda v: 0 if v == "benign" else 1)
    x = work_df.drop(columns=["Label"])
    x = x.apply(pd.to_numeric, errors="coerce")
    x = x.replace([float("inf"), float("-inf")], pd.NA).fillna(0.0)

    if y.nunique() < 2:
        raise HTTPException(
            status_code=500,
            detail="Bootstrap failed: Label column must contain benign and attack samples.",
        )

    x_train, _, y_train, _ = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )
    scaler = RobustScaler()
    x_train_scaled = pd.DataFrame(
        scaler.fit_transform(x_train), columns=x_train.columns, index=x_train.index
    )

    model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    model.fit(x_train_scaled, y_train)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save_model(str(MODEL_PATH))
    joblib.dump(scaler, SCALER_PATH)
    FEATURES_PATH.write_text(json.dumps(list(x_train.columns), indent=2), encoding="utf-8")
    return {"trained_rows": int(len(x_train))}


def _extract_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        parts = [p for p in stripped.split("```") if p.strip()]
        for part in parts:
            chunk = part.replace("json", "", 1).strip()
            try:
                return json.loads(chunk)
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _load_mitre_guide_text() -> str:
    """Full text from bundled MITRE guide PDF (cached)."""
    global _MITRE_GUIDE_TEXT_CACHE
    if _MITRE_GUIDE_TEXT_CACHE is not None:
        return _MITRE_GUIDE_TEXT_CACHE
    if not MITRE_GUIDE_PDF.exists():
        _MITRE_GUIDE_TEXT_CACHE = ""
        return ""
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(MITRE_GUIDE_PDF))
        parts: list[str] = []
        for page in reader.pages[:40]:
            parts.append(page.extract_text() or "")
        _MITRE_GUIDE_TEXT_CACHE = "\n".join(parts).strip()
    except Exception:
        _MITRE_GUIDE_TEXT_CACHE = ""
    return _MITRE_GUIDE_TEXT_CACHE


def _mitre_guide_excerpt(max_chars: int = 10000) -> str:
    text = _load_mitre_guide_text()
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[… مقتطف من الدليل …]"


# MITRE ATT&CK for ICS — official matrix order (https://attack.mitre.org/matrices/ics/)
_ICS_TACTIC_ORDER: list[str] = [
    "TA0108",  # Initial Access
    "TA0104",  # Execution
    "TA0110",  # Persistence
    "TA0111",  # Privilege Escalation
    "TA0103",  # Evasion
    "TA0102",  # Discovery
    "TA0109",  # Lateral Movement
    "TA0100",  # Collection
    "TA0101",  # Command and Control
    "TA0107",  # Inhibit Response Function
    "TA0106",  # Impair Process Control
    "TA0105",  # Impact
]

_ICS_TACTIC_ORDER_INDEX: dict[str, int] = {ta: i for i, ta in enumerate(_ICS_TACTIC_ORDER)}

_ICS_TA_AR: dict[str, str] = {
    "TA0108": "الوصول الأولي (ICS)",
    "TA0104": "التنفيذ (ICS)",
    "TA0110": "الإصرار / الاستمرارية (ICS)",
    "TA0111": "تصعيد الصلاحيات (ICS)",
    "TA0103": "التهرب (ICS)",
    "TA0102": "الاستطلاع والاكتشاف (ICS)",
    "TA0109": "الحركة الجانبية (ICS)",
    "TA0100": "الجمع (ICS)",
    "TA0101": "القيادة والتحكم (ICS)",
    "TA0107": "إعاقة وظيفة الاستجابة (ICS)",
    "TA0106": "إعاقة التحكم بالعملية (ICS)",
    "TA0105": "التأثير (ICS)",
}

# Primary ICS tactic per technique (Enterprise + common ICS T08xx). See attack.mitre.org/techniques/ics/
_TECHNIQUE_TO_ICS_TA: dict[str, str] = {
    "T1200": "TA0108",
    "T1091": "TA0109",
    "T1189": "TA0108",
    "T1190": "TA0108",
    "T1133": "TA0108",
    "T1566": "TA0108",
    "T0817": "TA0108",
    "T0822": "TA0108",
    "T0847": "TA0108",
    "T0886": "TA0108",
    "T1059": "TA0104",
    "T1203": "TA0104",
    "T1204": "TA0104",
    "T1106": "TA0104",
    "T0858": "TA0104",
    "T0807": "TA0104",
    "T0871": "TA0104",
    "T0853": "TA0110",
    "T1543": "TA0110",
    "T1547": "TA0110",
    "T1060": "TA0110",
    "T1078": "TA0111",
    "T0868": "TA0111",
    "T1110": "TA0111",
    "T0874": "TA0103",
    "T0856": "TA0103",
    "T1562": "TA0103",
    "T1046": "TA0102",
    "T1040": "TA0102",
    "T1049": "TA0102",
    "T1018": "TA0102",
    "T1087": "TA0102",
    "T0866": "TA0102",
    "T0867": "TA0102",
    "T0888": "TA0102",
    "T0846": "TA0102",
    "T0882": "TA0102",
    "T1021": "TA0109",
    "T1028": "TA0109",
    "T1550": "TA0109",
    "T1072": "TA0109",
    "T1105": "TA0109",
    "T1048": "TA0100",
    "T1020": "TA0100",
    "T1537": "TA0100",
    "T1005": "TA0100",
    "T1041": "TA0100",
    "T1213": "TA0100",
    "T1071": "TA0101",
    "T1567": "TA0101",
    "T1092": "TA0101",
    "T1573": "TA0101",
    "T0869": "TA0101",
    "T0884": "TA0101",
    "T0852": "TA0101",
    "T0809": "TA0107",
    "T0813": "TA0107",
    "T0815": "TA0107",
    "T0829": "TA0107",
    "T0837": "TA0107",
    "T0800": "TA0106",
    "T0806": "TA0106",
    "T0814": "TA0106",
    "T0827": "TA0106",
    "T0830": "TA0106",
    "T0831": "TA0106",
    "T0832": "TA0106",
    "T0855": "TA0106",
    "T0843": "TA0106",
    "T0845": "TA0106",
    "T0851": "TA0106",
    "T1498": "TA0105",
    "T1499": "TA0105",
    "T1496": "TA0105",
}


def _technique_to_ics_tactic_id(technique_id: str) -> str:
    tid = str(technique_id).upper().split(".")[0]
    if tid in _TECHNIQUE_TO_ICS_TA:
        return _TECHNIQUE_TO_ICS_TA[tid]
    if tid.startswith("T08"):
        return "TA0106"
    return "TA0102"


def _tactic_meta_for_technique(technique_id: str) -> tuple[str, str]:
    ta = _technique_to_ics_tactic_id(technique_id)
    name_ar = _ICS_TA_AR.get(ta, "مرحلة ICS غير مُصنّفة")
    return ta, name_ar


def _has_arabic_script(text: str) -> bool:
    return any("\u0600" <= c <= "\u06ff" for c in str(text or ""))


def _is_generic_english_timeline_title(title: str) -> bool:
    t = str(title or "").lower().strip()
    if not t:
        return True
    needles = (
        "suspicious network",
        "network behavior",
        "network anomaly",
        "malicious behavior",
        "potential attack",
        "attack detected",
        "suspicious activity",
        "anomaly detected",
    )
    return any(n in t for n in needles)


def _merge_timeline_prefer_arabic_evidence(
    model_timeline: list[Any],
    base_timeline: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Keep model ordering/mitres when useful; restore Arabic titles from measured base timeline."""
    if not isinstance(model_timeline, list) or not model_timeline:
        return [dict(x) for x in base_timeline] if base_timeline else []

    def _norm_title(x: Any) -> str:
        return " ".join(str(x or "").split()).lower()

    model_titles = [
        _norm_title(item.get("title"))
        for item in model_timeline
        if isinstance(item, dict) and _norm_title(item.get("title"))
    ]
    if model_titles:
        uniq_titles = len(set(model_titles))
        # If Gemini repeats nearly the same title across many events, trust measured timeline.
        if len(model_titles) >= 4 and uniq_titles <= max(2, len(model_titles) // 3):
            return [dict(x) for x in base_timeline] if base_timeline else []

    out: list[dict[str, str]] = []
    for i, item in enumerate(model_timeline):
        if not isinstance(item, dict):
            continue
        ref = base_timeline[i] if i < len(base_timeline) else None
        title = str(item.get("title") or "").strip()
        detail = str(item.get("detail") or "").strip()
        time_s = str(item.get("time") or "")
        mitre_s = str(item.get("mitre") or "")
        if ref:
            rt = str(ref.get("title") or "").strip()
            rd = str(ref.get("detail") or "").strip()
            if (not _has_arabic_script(title) and _has_arabic_script(rt)) or (
                _is_generic_english_timeline_title(title) and rt
            ):
                title = rt
                detail = rd or detail
            if not time_s:
                time_s = str(ref.get("time") or "")
            if not mitre_s:
                mitre_s = str(ref.get("mitre") or "")
        out.append(
            {
                "time": time_s or "—",
                "title": title or (str(ref.get("title")) if ref else "") or "حدث مشبوه",
                "mitre": mitre_s or (str(ref.get("mitre")) if ref else "") or "MITRE: T1071",
                "detail": detail or (str(ref.get("detail")) if ref else "") or "",
            }
        )
    return out if out else [dict(x) for x in base_timeline]


def _collapse_mitre_stage_nodes(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One technique card per stage; extra techniques move into evidence_ar (no duplicate cards)."""
    out: list[dict[str, Any]] = []
    for st in stages:
        if not isinstance(st, dict):
            continue
        nodes_in = st.get("nodes") or []
        if not nodes_in:
            continue
        nodes_clean = [n for n in nodes_in if isinstance(n, dict)]
        if not nodes_clean:
            continue
        primary = dict(nodes_clean[0])
        extras: list[str] = []
        extra_evidence: list[str] = []
        for n in nodes_clean[1:]:
            tid = str(n.get("technique_id") or "").strip().upper()
            if tid:
                extras.append(tid)
            ev = str(n.get("evidence_ar") or n.get("detail_ar") or "").strip()
            if ev:
                extra_evidence.append(ev)
        ev = str(primary.get("evidence_ar") or "").strip()
        bits: list[str] = []
        if extras:
            bits.append("تقنيات مرتبطة: " + "، ".join(dict.fromkeys(extras)))
        if extra_evidence:
            bits.append("؛ ".join(dict.fromkeys(extra_evidence)))
        if bits:
            primary["evidence_ar"] = (ev + " — " if ev else "") + " ".join(bits)
        tac_id, tac_ar = _tactic_meta_for_technique(str(primary.get("technique_id") or ""))
        new_st = {
            **st,
            "tactic_id": tac_id,
            "tactic_ar": tac_ar,
            "nodes": [primary],
        }
        out.append(new_st)
    return out


def _dedupe_mitre_stages_by_node_fingerprint(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate steps; keep earliest for same tactic+technique."""
    seen_exact: set[str] = set()
    seen_tactic_technique: set[str] = set()
    out: list[dict[str, Any]] = []
    for st in stages:
        nodes = st.get("nodes") or []
        if not nodes or not isinstance(nodes[0], dict):
            continue
        n0 = nodes[0]
        tac = str(st.get("tactic_id") or "").strip().upper()
        tid = str(n0.get("technique_id") or "")
        tm = str(n0.get("time") or "")
        nar = " ".join(str(n0.get("name_ar") or "").split())[:120]
        fp_exact = f"{tid}|{tm}|{nar}"
        fp_tt = f"{tac}|{tid}"
        if fp_exact in seen_exact:
            continue
        # For attack-path readability: one stage per tactic+technique.
        if tac and tid and fp_tt in seen_tactic_technique:
            continue
        seen_exact.add(fp_exact)
        if tac and tid:
            seen_tactic_technique.add(fp_tt)
        out.append(st)
    for i, st in enumerate(out, start=1):
        st["order"] = i
    return out


def _sanitize_mitre_stages_pipeline(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    collapsed = _collapse_mitre_stage_nodes(stages)
    ordered = _reorder_mitre_stages_ics_canonical(collapsed)
    return _dedupe_mitre_stages_by_node_fingerprint(ordered)


def _reorder_mitre_stages_ics_canonical(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort stages by ATT&CK for ICS matrix order; renumber order fields."""

    def sort_key(st: dict[str, Any]) -> tuple[int, int, str]:
        tac = str(st.get("tactic_id") or "").strip()
        nodes = st.get("nodes") or []
        if tac not in _ICS_TACTIC_ORDER_INDEX and nodes:
            n0 = nodes[0] if isinstance(nodes[0], dict) else {}
            tid = str(n0.get("technique_id") or "")
            if tid:
                tac = _technique_to_ics_tactic_id(tid)
                st["tactic_id"] = tac
                st["tactic_ar"] = _ICS_TA_AR.get(tac, str(st.get("tactic_ar") or ""))
        idx = _ICS_TACTIC_ORDER_INDEX.get(tac, 999)
        sub = int(st.get("order") or 0)
        first_tid = ""
        if nodes and isinstance(nodes[0], dict):
            first_tid = str(nodes[0].get("technique_id") or "")
        return (idx, sub, first_tid)

    ordered = sorted(stages, key=sort_key)
    for i, st in enumerate(ordered, start=1):
        st["order"] = i
    return ordered


def _extract_technique_ids(text: str) -> list[str]:
    if not text:
        return []
    return list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", text, flags=re.I)))


def _wall_clock_column(df: pd.DataFrame) -> str | None:
    """Use real timestamps only — never Flow Duration (microseconds of flow), which breaks 'time sync'."""
    for col in (
        "Timestamp",
        "timestamp",
        "DateTime",
        "datetime",
        "EventTime",
        "event_time",
        "TIME",
        "Time",
        "time",
    ):
        if col in df.columns:
            return col
    return None


def _format_timeline_timestamp(raw: Any) -> str:
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return "—"
    s = str(raw).strip()
    if not s:
        return "—"
    parsed = pd.to_datetime(s, utc=True, errors="coerce")
    if pd.notna(parsed):
        try:
            return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError):
            pass
    return s


def _timeline_from_explicit_mitre_logs(
    df: pd.DataFrame,
    probs: pd.Series,
    top_n: int = 8,
) -> list[dict[str, str]]:
    """
    Prefer explicit MITRE log fields when present (e.g., usb_injection_mitre_training_dataset.csv):
    mitre_id / mitre_tactic / event_name / description / timestamp.
    """
    cols = {str(c).strip().lower(): c for c in df.columns}
    mitre_id_col = cols.get("mitre_id")
    if not mitre_id_col:
        return []

    tactic_col = cols.get("mitre_tactic")
    event_col = cols.get("event_name") or cols.get("event_category")
    desc_col = cols.get("description")
    status_col = cols.get("status")
    pred_col = cols.get("xgboost_prediction")
    conf_col = cols.get("xgboost_confidence")
    time_col = _wall_clock_column(df) or cols.get("timestamp")

    candidate_idx: list[int] = []
    for ridx in df.index:
        mid = str(df.loc[ridx, mitre_id_col]).strip() if mitre_id_col in df.columns else ""
        if not mid or mid == "-":
            continue

        keep = False
        if status_col:
            status_v = str(df.loc[ridx, status_col]).strip().lower()
            if status_v in {"malicious", "suspicious"}:
                keep = True
        if not keep and pred_col:
            pv = str(df.loc[ridx, pred_col]).strip().lower()
            if pv == "malicious":
                keep = True
        if not keep:
            # fallback to model score when explicit status is unavailable.
            try:
                keep = float(probs.loc[ridx]) >= 0.5
            except Exception:
                keep = False
        if keep:
            candidate_idx.append(int(ridx))

    if not candidate_idx:
        return []

    def _sort_key(ix: int) -> tuple[int, int]:
        if time_col and time_col in df.columns:
            t = pd.to_datetime(df.loc[ix, time_col], utc=True, errors="coerce")
            if pd.notna(t):
                return (0, int(t.value))
        return (1, ix)

    candidate_idx = sorted(candidate_idx, key=_sort_key)[: max(12, top_n)]

    events: list[dict[str, str]] = []
    for ix in candidate_idx:
        mitre_id_raw = str(df.loc[ix, mitre_id_col]).strip().upper()
        if not mitre_id_raw or mitre_id_raw == "-":
            continue
        m = re.search(r"T\d{4}(?:\.\d{3})?", mitre_id_raw, flags=re.I)
        tid = m.group(0).upper() if m else "T1071"

        tactic = (
            str(df.loc[ix, tactic_col]).strip()
            if tactic_col and tactic_col in df.columns
            else ""
        )
        event_name = (
            str(df.loc[ix, event_col]).strip()
            if event_col and event_col in df.columns
            else ""
        )
        desc = (
            str(df.loc[ix, desc_col]).strip()
            if desc_col and desc_col in df.columns
            else ""
        )
        ts = (
            _format_timeline_timestamp(df.loc[ix, time_col])
            if time_col and time_col in df.columns
            else f"صف-{ix}"
        )
        score = float(probs.loc[ix]) if ix in probs.index else 0.0
        conf_note = ""
        if conf_col and conf_col in df.columns:
            try:
                conf_note = f"؛ ثقة السجل={float(df.loc[ix, conf_col]):.2f}"
            except (TypeError, ValueError):
                conf_note = ""

        title_ar = (
            f"{event_name} ({tactic})"
            if event_name and tactic
            else (event_name or f"حدث مُصنّف ضمن {tactic}" if tactic else "حدث أمني مشبوه")
        )
        detail_ar = (
            f"P(malicious)={score:.3f}{conf_note}"
            + (f"؛ الوصف: {desc}" if desc else "")
        )

        events.append(
            {
                "time": ts,
                "title": title_ar,
                "mitre": f"MITRE: {tid}",
                "detail": detail_ar,
            }
        )

    return events


def _timeline_from_data(df: pd.DataFrame, probs: pd.Series, top_n: int = 8) -> list[dict[str, str]]:
    explicit = _timeline_from_explicit_mitre_logs(df, probs, top_n=top_n)
    if explicit:
        return explicit

    malicious_idx = probs.sort_values(ascending=False).head(top_n).index.tolist()
    time_column = _wall_clock_column(df)
    if time_column:
        keyed: list[tuple[Any, pd.Timestamp | None]] = []
        for idx in malicious_idx:
            raw = df.loc[idx, time_column]
            t = pd.to_datetime(raw, utc=True, errors="coerce")
            keyed.append((idx, t if pd.notna(t) else None))
        keyed.sort(
            key=lambda it: (
                1 if it[1] is None else 0,
                it[1].value if it[1] is not None else 0,
                str(it[0]),
            )
        )
        malicious_idx = [k[0] for k in keyed]
    events: list[dict[str, str]] = []
    for idx in malicious_idx:
        row = df.loc[idx]
        if time_column:
            ts = _format_timeline_timestamp(row[time_column])
        else:
            ts = f"صف-{idx}"
        score = float(probs.loc[idx])
        ev = _row_evidence_snapshot(df, int(idx), score)
        tags = ev.get("context_tags") or []

        if "usb_or_removable_context" in tags:
            title_ar = "إشارة تفاعل وسيط تخزين خارجي / USB ضمن سجل مشبوه"
            tids = ["T0847", "T1091"]
            detail = (
                f"P(malicious)={score:.3f}؛ مؤشرات USB ومعدلات I/O الخارجي مرتفعة في هذا السجل."
            )
        elif "elevated_scada_command_pattern" in tags:
            title_ar = "نمط أوامر/تحكم صناعي غير متماثل مع خط الأساس"
            tids = ["T0855", "T0831"]
            detail = (
                f"P(malicious)={score:.3f}؛ ارتفاع نسبي في معدلات أوامر SCADA/ICS في العينة."
            )
        elif "handshake_stress_pattern" in tags:
            title_ar = "ضغط مصافحة TCP / مسح خدمات محتمل على الشبكة"
            tids = ["T1046", "T1071"]
            detail = (
                f"P(malicious)={score:.3f}؛ ارتفاع أعلام SYN/RST مقارنة ببقية التدفقات."
            )
        else:
            km = ev.get("key_metrics") or {}
            bps = km.get("Flow Bytes/s")
            if bps is not None and bps > 15000:
                title_ar = "تدفق بيانات شبكي كثيف قد يدعم قناة C2 أو نقل حمولة"
                tids = ["T1071", "T1041"]
            else:
                title_ar = "سلوك شبكي شاذ مبرر عددياً (IDS / تعلّم آلي)"
                tids = ["T1071", "T1046"]
            devs = ev.get("top_deviations") or []
            top_c = ", ".join(d["column"] for d in devs[:3]) if devs else "عدة حقول رقمية"
            detail = f"P(malicious)={score:.3f}؛ أبرز انحرافات الحقول: {top_c}."

        mitre_str = "MITRE: " + " / ".join(tids)
        events.append(
            {
                "time": ts,
                "title": title_ar,
                "mitre": mitre_str,
                "detail": detail,
            }
        )
    return events


def _fallback_mitre_attack_map(
    timeline: list[dict[str, Any]],
    summary: dict[str, Any],
    row_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    stages: list[dict[str, Any]] = []
    if not timeline:
        rate = float(summary.get("malicious_rate", 0)) * 100
        stages = [
            {
                "order": 1,
                "tactic_id": "TA0102",
                "tactic_ar": _ICS_TA_AR["TA0102"],
                "nodes": [
                    {
                        "technique_id": "T1046",
                        "name_ar": "لا توجد سلسلة زمنية مفصلة في الملف؛ راجع الملخص والسجلات المشبوهة.",
                        "name_en": "",
                        "evidence_ar": f"نسبة سلوك ضار تقريبية {rate:.1f}% من النموذج.",
                        "time": "",
                    }
                ],
            }
        ]
        narrative = (
            "لم يُستخرج تسلسل زمني من أعمدة الوقت في CSV؛ يُعرض مرحلة استطلاع (ICS) افتراضية. "
            "المراحل الأخرى تتبع ترتيب ماتريكس MITRE ATT&CK للأنظمة الصناعية عند توفر بيانات. "
            f"أعد رفع ملفاً يحتوي أعمدة زمنية إن وُجدت، أو راجع بطاقات المحقق."
        )
        return {"narrative_ar": narrative, "stages": stages}

    for i, step in enumerate(timeline[:12]):
        mitre_raw = str(step.get("mitre", ""))
        tids = _extract_technique_ids(mitre_raw)
        if not tids:
            tids = ["T1071"]
        primary = tids[0]
        ta_id, tactic_ar = _tactic_meta_for_technique(primary)
        detail = str(step.get("detail", ""))
        extra = [x for x in tids[1:3] if x != primary]
        evidence = detail
        if extra:
            evidence = (
                (detail + " — ") if detail else ""
            ) + "تقنيات مرتبطة: " + "، ".join(extra)
        stages.append(
            {
                "order": i + 1,
                "tactic_id": ta_id,
                "tactic_ar": tactic_ar,
                "nodes": [
                    {
                        "technique_id": primary,
                        "name_ar": str(step.get("title", "حدث مشبوه")),
                        "name_en": "",
                        "evidence_ar": evidence,
                        "time": str(step.get("time", "")),
                    }
                ],
            }
        )

    ev_note = ""
    if row_evidence:
        tags = {t for block in row_evidence for t in (block.get("context_tags") or [])}
        if tags:
            ev_note = f" وسياقات مُستخرجة: {', '.join(sorted(tags))}."

    stages = _sanitize_mitre_stages_pipeline(stages)
    narrative = (
        f"مسار مُستنتج وفق ترتيب ماتريكس MITRE ATT&CK للأنظمة الصناعية (ICS) "
        f"(attack.mitre.org/matrices/ics/) من أشد السجلات خطورة "
        f"(نسبة سلوك ضار إجمالية {float(summary.get('malicious_rate', 0)) * 100:.1f}%). "
        f"استخدم العقد أدناه لربط الأدلة الرقمية بالتكتيكات.{ev_note}"
    )
    return {"narrative_ar": narrative, "stages": stages}


def _coerce_mitre_nodes_list(st: dict[str, Any]) -> list[Any]:
    """Gemini / models may use nodes, techniques, or a single dict."""
    nodes_in = st.get("nodes")
    if isinstance(nodes_in, list) and nodes_in:
        return nodes_in
    alt = st.get("techniques") or st.get("Techniques")
    if isinstance(alt, list) and alt:
        return alt
    single = st.get("node") or st.get("technique")
    if isinstance(single, dict):
        return [single]
    return []


def _normalize_mitre_attack_map(
    raw: Any,
    timeline: list[dict[str, Any]],
    summary: dict[str, Any],
    row_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    if isinstance(raw, dict) and isinstance(raw.get("mitre_attack_map"), dict):
        raw = raw["mitre_attack_map"]
    if isinstance(raw, list) and raw and all(isinstance(x, dict) for x in raw[:5]):
        raw = {"stages": raw, "narrative_ar": ""}
    if isinstance(raw, dict) and isinstance(raw.get("stages"), list) and raw["stages"]:
        stages_in = raw["stages"]
        stages_out: list[dict[str, Any]] = []
        for i, st in enumerate(stages_in[:14]):
            if not isinstance(st, dict):
                continue
            nodes_in = _coerce_mitre_nodes_list(st)
            if not nodes_in:
                continue
            nodes_out: list[dict[str, Any]] = []
            for n in nodes_in[:4]:
                if not isinstance(n, dict):
                    continue
                tid_raw = (
                    n.get("technique_id")
                    or n.get("id")
                    or n.get("mitre_id")
                    or n.get("technique")
                    or ""
                )
                tid = str(tid_raw).strip().upper()
                if not tid.startswith("T"):
                    m = re.search(r"T\d{4}(?:\.\d{3})?", tid)
                    tid = m.group(0) if m else "T1071"
                nodes_out.append(
                    {
                        "technique_id": tid,
                        "name_ar": str(n.get("name_ar") or n.get("label_ar") or "تقنية"),
                        "name_en": str(n.get("name_en") or ""),
                        "evidence_ar": str(
                            n.get("evidence_ar") or n.get("detail_ar") or ""
                        ),
                        "time": str(n.get("time") or ""),
                    }
                )
            if not nodes_out:
                continue
            tac_id, tac_ar = _tactic_meta_for_technique(nodes_out[0]["technique_id"])
            stages_out.append(
                {
                    "order": int(st.get("order") or i + 1),
                    "tactic_id": tac_id,
                    "tactic_ar": tac_ar,
                    "nodes": nodes_out,
                }
            )
        if stages_out:
            stages_out = _sanitize_mitre_stages_pipeline(stages_out)
            nar = raw.get("narrative_ar") or raw.get("summary_ar")
            if not isinstance(nar, str) or not nar.strip():
                nar = _fallback_mitre_attack_map(timeline, summary, row_evidence)[
                    "narrative_ar"
                ]
            return {"narrative_ar": nar.strip(), "stages": stages_out}

    return _fallback_mitre_attack_map(timeline, summary, row_evidence)


def _attack_family_scores_from_key_metrics(key_metrics: dict[str, float]) -> dict[str, float]:
    """
    CIC-IDS-2017–style flow heuristics for attack *family* hints (not a second model).
    Scores are relative within the row; combined with XGBoost P(malicious) in /analyze.
    """
    fps = float(key_metrics.get("Flow Packets/s") or 0)
    fbs = float(key_metrics.get("Flow Bytes/s") or 0)
    syn = float(key_metrics.get("SYN Flag Count") or 0)
    rst = float(key_metrics.get("RST Flag Count") or 0)
    psh = float(key_metrics.get("PSH Flag Count") or 0)
    down_up = float(key_metrics.get("Down/Up Ratio") or 0)
    tfwd = float(key_metrics.get("Total Fwd Packets") or 0)
    tbwd = float(key_metrics.get("Total Backward Packets") or 0)

    scores = {
        "DDoS / Flood": 0.0,
        "Port scan / probe": 0.0,
        "C2 or bulk transfer": 0.0,
        "Web / application-layer": 0.0,
    }
    if fps > 80 or (fbs > 40000 and fps > 25):
        scores["DDoS / Flood"] += 0.55
    elif fps > 35 or fbs > 20000:
        scores["DDoS / Flood"] += 0.28
    if syn >= 15 and rst >= 4:
        scores["Port scan / probe"] += 0.5
    elif syn >= 8 and rst >= 3:
        scores["Port scan / probe"] += 0.26
    if fbs > 15000 and psh >= 1 and 0.15 <= down_up <= 6:
        scores["Web / application-layer"] += 0.22
    if fbs > 12000 and (tfwd + tbwd) < 250 and fps < 40:
        scores["C2 or bulk transfer"] += 0.2
    m = max(scores.values()) or 1e-9
    return {k: round(v / m, 4) for k, v in scores.items()}


def _feature_importance_top(
    model: xgb.XGBClassifier, feature_columns: list[str], k: int = 12
) -> list[dict[str, Any]]:
    try:
        booster = model.get_booster()
        raw = booster.get_score(importance_type="gain")
        if not raw:
            return []
        items: list[tuple[str, float]] = []
        if all(str(name).startswith("f") and str(name)[1:].isdigit() for name in raw):
            for fname, gain in raw.items():
                idx = int(str(fname)[1:])
                if 0 <= idx < len(feature_columns):
                    items.append((feature_columns[idx], float(gain)))
        else:
            for name, gain in raw.items():
                items.append((str(name), float(gain)))
        items.sort(key=lambda x: -x[1])
        tot = sum(g for _, g in items) or 1.0
        return [
            {"feature": n, "gain": round(g, 4), "importance_pct": round(100.0 * g / tot, 2)}
            for n, g in items[:k]
        ]
    except Exception:
        return []


def _build_custody_chain(
    filename: str,
    hashes: dict[str, str],
    byte_len: int,
    summary: dict[str, Any],
    inference_mode: str,
    investigator_name: str | None = None,
) -> list[dict[str, Any]]:
    base = datetime.utcnow()
    sha = hashes.get("SHA256", "")
    steps: list[dict[str, str]] = [
        {
            "step_ar": "رفع الدليل الرقمي",
            "detail_ar": f"الملف: {filename} — الحجم {byte_len:,} بايت.",
        },
        {
            "step_ar": "حساب الهاش",
            "detail_ar": f"SHA256={sha}؛ وSHA1/MD5/BLAKE2B/SHA3-256 لسلسلة الحيازة.",
        },
        {
            "step_ar": "كشف السجلات المشبوهة آلياً",
            "detail_ar": (
                f"تصنيف كل سجل (سلوك ضار مقابل طبيعي) عبر نموذج تعلم آلي؛ "
                f"نمط الاستدلال: {inference_mode}؛ عدد السجلات: {summary.get('total_records', 0)}؛ "
                f"نسبة السلوك الضار: {float(summary.get('malicious_rate', 0)) * 100:.2f}%. "
                f"(النموذج مُقيَّم بمسار تدريب شبيه بمجموعة CIC-IDS-2017.)"
            ),
        },
        {
            "step_ar": "تحليل السجلات المشبوهة",
            "detail_ar": (
                "تحليل مُعمّق للسجلات ذات الاشتباه الأعلى، وربطها بمسار MITRE والتوصيات والتقرير "
                "عند تفعيل Gemini، مع الالتزام بالأدلة المستخرجة من الملف دون اختلاق وقائع."
            ),
        },
    ]
    inv = (investigator_name or "").strip()
    if inv:
        steps.append(
            {
                "step_ar": f"تم الرفع بواسطة المحقق {inv}",
                "detail_ar": (
                    "توثيق اسم المحقق المسؤول عن رفع الدليل الرقمي ضمن سلسلة الحيازة."
                ),
            }
        )
    out: list[dict[str, Any]] = []
    for i, st in enumerate(steps):
        ts = (base + timedelta(seconds=i * 2)).isoformat() + "Z"
        out.append({**st, "at": ts})
    return out


def _custody_chain_markdown(chain: list[dict[str, Any]]) -> str:
    lines = ["## سلسلة الحيازة والخطوات التقنية", ""]
    for i, step in enumerate(chain, 1):
        title = str(step.get("step_ar") or "").strip()
        at = str(step.get("at") or "").strip()
        detail = str(step.get("detail_ar") or "").strip()
        lines.append(f"{i}. **{title}** — `{at}`")
        if detail:
            lines.append(f"    - {detail}")
        lines.append("")
    return "\n".join(lines).strip()


def _aggregate_attack_profile(
    row_evidence: list[dict[str, Any]], top_suspicious_rows: list[dict[str, Any]]
) -> tuple[str, dict[str, float]]:
    agg: dict[str, float] = defaultdict(float)
    wtot = 0.0
    for ev, row in zip(row_evidence, top_suspicious_rows):
        w = float(row.get("score", 0))
        fams = ev.get("inferred_attack_families") or {}
        if isinstance(fams, dict):
            for k, v in fams.items():
                try:
                    agg[str(k)] += float(v) * w
                except (TypeError, ValueError):
                    continue
        wtot += w
    if not agg or wtot <= 0:
        return "غير محدد — راجع احتمالات النموذج والحقول", {}
    profile = {
        k: round(v / wtot, 4) for k, v in sorted(agg.items(), key=lambda x: -x[1])[:8]
    }
    primary = max(profile.items(), key=lambda x: x[1])[0]
    return primary, profile


def _heuristic_probabilities(df: pd.DataFrame) -> pd.Series:
    numeric_df = df.select_dtypes(include=["number"]).copy()
    if numeric_df.empty:
        return pd.Series([0.05] * len(df), index=df.index, dtype=float)

    numeric_df = numeric_df.replace([float("inf"), float("-inf")], pd.NA).fillna(0.0)
    z_scores = (numeric_df - numeric_df.mean()) / (numeric_df.std(ddof=0).replace(0, 1))
    anomaly_score = z_scores.abs().mean(axis=1)
    norm = (anomaly_score - anomaly_score.min()) / (
        (anomaly_score.max() - anomaly_score.min()) or 1
    )
    probs = 0.05 + 0.9 * norm
    return probs.astype(float)


_EVIDENCE_PRIORITY_COLS = [
    "USB_Insert_Flag",
    "External_Device_IO_Rate",
    "SCADA_Command_Rate",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow Duration",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
]


def _priority_from_score(score: float) -> str:
    if score >= 0.95:
        return "Critical"
    if score >= 0.85:
        return "High"
    return "Medium"


def _row_evidence_snapshot(df: pd.DataFrame, row_index: int, risk_score: float) -> dict[str, Any]:
    """Per-row numeric/text facts so findings are unique and investigator-actionable."""
    out: dict[str, Any] = {
        "row_index": int(row_index),
        "risk_score": round(float(risk_score), 4),
    }
    if row_index not in df.index:
        out["note"] = "row_index_not_in_dataframe"
        return out

    row = df.loc[row_index]
    if "Label" in df.columns:
        try:
            lab = row["Label"]
            if pd.notna(lab):
                out["dataset_label"] = str(lab).strip()
        except (KeyError, TypeError, ValueError):
            pass
    wall_col = _wall_clock_column(df)
    if wall_col:
        try:
            out["event_time_display"] = _format_timeline_timestamp(row[wall_col])
        except (KeyError, TypeError, ValueError):
            pass
    work_num = df.drop(columns=["Label"], errors="ignore").select_dtypes(include=["number"])
    work_num = work_num.replace([float("inf"), float("-inf")], pd.NA).fillna(0.0)

    key_metrics: dict[str, float] = {}
    for col in _EVIDENCE_PRIORITY_COLS:
        if col in df.columns:
            try:
                raw = pd.to_numeric(row[col], errors="coerce")
                key_metrics[col] = float(raw) if pd.notna(raw) else 0.0
            except (TypeError, ValueError):
                key_metrics[col] = 0.0
    out["key_metrics"] = key_metrics

    text_snippets: dict[str, str] = {}
    for col in df.columns:
        if col == "Label" or col in work_num.columns:
            continue
        val = row[col]
        if pd.isna(val):
            continue
        s = str(val).strip()
        if s:
            text_snippets[col] = s[:160]
        if len(text_snippets) >= 8:
            break
    if text_snippets:
        out["text_fields"] = text_snippets

    tags: list[str] = []
    usb_v = key_metrics.get("USB_Insert_Flag")
    if usb_v is not None and usb_v >= 0.5:
        tags.append("usb_or_removable_context")
    scada = key_metrics.get("SCADA_Command_Rate")
    if scada is not None and len(work_num) > 2:
        med = float(work_num["SCADA_Command_Rate"].median()) if "SCADA_Command_Rate" in work_num else 0.0
        if scada > med * 2 and scada > 1e-6:
            tags.append("elevated_scada_command_pattern")
    syn = key_metrics.get("SYN Flag Count")
    rst = key_metrics.get("RST Flag Count")
    if syn is not None and rst is not None and syn >= 8 and rst >= 5:
        tags.append("handshake_stress_pattern")
    if not work_num.empty and row_index in work_num.index:
        med = work_num.median()
        std = work_num.std(ddof=0).replace(0, 1e-9)
        vals = work_num.loc[row_index]
        z_series = (vals - med) / std
        order = z_series.abs().sort_values(ascending=False).head(8).index.tolist()
        top_deviations: list[dict[str, Any]] = []
        for col in order:
            top_deviations.append(
                {
                    "column": col,
                    "value": round(float(vals[col]), 6),
                    "median": round(float(med[col]), 6),
                    "z_score": round(float(z_series[col]), 3),
                }
            )
        out["top_deviations"] = top_deviations
        out["evidence_bullets"] = [
            f"{d['column']}: {d['value']} (Z-score {d['z_score']:+.1f})"
            for d in top_deviations[:5]
        ]
    if tags:
        out["context_tags"] = tags

    if key_metrics:
        fam = _attack_family_scores_from_key_metrics(key_metrics)
        out["inferred_attack_families"] = fam

    return out


def _build_row_evidence_list(
    df: pd.DataFrame, top_suspicious_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return [
        _row_evidence_snapshot(df, int(item["row_index"]), float(item["score"]))
        for item in top_suspicious_rows
    ]


def _resolve_feature_columns(scaler, model: xgb.XGBClassifier) -> list[str]:
    feature_columns = _read_feature_columns()
    if feature_columns:
        return feature_columns

    if hasattr(scaler, "feature_names_in_"):
        feature_names = list(scaler.feature_names_in_)
        if feature_names:
            return feature_names

    booster_names = model.get_booster().feature_names or []
    if booster_names:
        return list(booster_names)

    raise HTTPException(
        status_code=500,
        detail=(
            "Could not resolve feature columns. Provide feature_columns.json or "
            "re-export scaler/model with feature names."
        ),
    )


def _normalize_col_name(name: str) -> str:
    return "".join(str(name).strip().lower().split())


def _align_columns_with_training_schema(
    df: pd.DataFrame, feature_columns: list[str]
) -> tuple[pd.DataFrame, list[str]]:
    aligned = df.copy()
    normalized_to_actual = {_normalize_col_name(col): col for col in aligned.columns}
    renamed = {}
    for expected in feature_columns:
        if expected in aligned.columns:
            continue
        normalized_expected = _normalize_col_name(expected)
        if normalized_expected in normalized_to_actual:
            actual_col = normalized_to_actual[normalized_expected]
            renamed[actual_col] = expected

    if renamed:
        aligned = aligned.rename(columns=renamed)

    missing_cols = [c for c in feature_columns if c not in aligned.columns]
    return aligned, missing_cols


def _format_timeline_item_for_report_md(item: dict[str, Any]) -> str:
    """One timeline line: `TIME: title (MITRE: …) - details` (matches formal report style)."""
    t = str(item.get("time") or "-").strip()
    title = str(item.get("title") or "-").strip()
    mitre = str(item.get("mitre") or "").strip()
    detail = str(item.get("detail") or "").strip()
    mitre_part = f" ({mitre})" if mitre else ""
    dash = " - " if detail else ""
    return f"- {t}: {title}{mitre_part}{dash}{detail}"


def _severity_label_from_rate(malicious_rate: float) -> str:
    if malicious_rate > 0.35:
        return "عالية"
    if malicious_rate > 0.1:
        return "متوسطة"
    return "منخفضة"


def _ensure_final_report_has_severity(text: str, malicious_rate: float) -> str:
    ft = (text or "").strip()
    if not ft:
        return f"تصنيف الشدة الإجمالي: {_severity_label_from_rate(malicious_rate)}."
    if "تصنيف الشدة الإجمالي" in ft:
        return ft
    sep = "" if ft.endswith(".") else "."
    return f"{ft}{sep} تصنيف الشدة الإجمالي: {_severity_label_from_rate(malicious_rate)}."


def _suspicious_findings_report_md(findings: list[dict[str, Any]] | None) -> str | None:
    if not findings:
        return None
    lines: list[str] = []
    for f in findings[:8]:
        if not isinstance(f, dict):
            continue
        rid = f.get("row_index", "?")
        score = float(f.get("risk_score", 0) or 0) * 100
        sp = str(f.get("suspected_process_or_file") or "").strip()
        why = str(f.get("why_malicious") or "").strip()
        nxt = str(f.get("investigator_next_step") or "").strip()
        body = f"- **الصف {rid}** (احتمال نموذجي **{score:.2f}%**)"
        if sp:
            body += f": {sp}"
        if why:
            w = why if len(why) <= 400 else why[:397] + "…"
            body += f"\n  - **لماذا يبدو مشبوهاً:** {w}"
        if nxt:
            n = nxt if len(nxt) <= 220 else nxt[:217] + "…"
            body += f"\n  - **خطوة المحقق:** {n}"
        lines.append(body)
    if not lines:
        return None
    return "\n".join(lines)


def _build_fallback_markdown(
    summary: dict[str, Any],
    timeline: list[dict[str, Any]],
    recommendations: list[str],
    final_report: str,
    top_suspicious_rows: list[dict[str, Any]],
    suspicious_findings: list[dict[str, Any]] | None = None,
) -> str:
    total = summary.get("total_records", 0)
    malicious = summary.get("malicious_count", 0)
    rate_pct = float(summary.get("malicious_rate", 0.0) or 0.0) * 100
    avg_pct = float(summary.get("average_malicious_probability", 0.0) or 0.0) * 100
    high_risk = summary.get("high_risk_count", 0)
    mode = summary.get("inference_mode", "unknown")

    summary_section = (
        "## ملخص التنبؤات\n\n"
        f"- إجمالي السجلات: **{total}**\n"
        f"- السجلات الضارة: **{malicious}**\n"
        f"- نسبة السلوك الضار: **{rate_pct:.2f}%**\n"
        f"- متوسط احتمال الهجوم: **{avg_pct:.2f}%**\n"
        f"- تدفقات عالية الخطورة: **{high_risk}**\n"
        f"- نمط الاستدلال: **{mode}**\n"
    )

    suspicious_lines: list[str] = []
    for row in top_suspicious_rows:
        if not isinstance(row, dict):
            continue
        ri = row.get("row_index", "-")
        sc = float(row.get("score", 0) or 0) * 100
        suspicious_lines.append(f"- الصف {ri}: احتمال الهجوم {sc:.2f}%")
    suspicious_md = (
        "\n".join(suspicious_lines)
        if suspicious_lines
        else "- لا توجد سجلات مشبوهة مُبرزة في هذه العيّنة."
    )

    findings_block = _suspicious_findings_report_md(suspicious_findings)

    timeline_lines: list[str] = []
    for item in timeline:
        if isinstance(item, dict):
            timeline_lines.append(_format_timeline_item_for_report_md(item))
    timeline_md = (
        "\n".join(timeline_lines)
        if timeline_lines
        else "- لا يوجد تسلسل زمني مُستخرج من البيانات."
    )

    rec_md = "\n".join(f"- {item}" for item in recommendations) if recommendations else "- لا توجد توصيات."

    conclusion = (final_report or "").strip() or "لم تُنجز خلاصة آلية."

    parts = [
        "# التقرير الجنائي الرقمي",
        "",
        summary_section,
        "## أعلى السجلات المشبوهة",
        "",
        suspicious_md,
        "",
    ]
    if findings_block:
        parts.extend(
            [
                "## تحليل السجلات المشبوهة (تفصيل المحقق)",
                "",
                findings_block,
                "",
            ]
        )
    parts.extend(
        [
            "## التسلسل الزمني للهجوم",
            "",
            timeline_md,
            "",
            "## توصيات عاجلة",
            "",
            rec_md,
            "",
            "## الخلاصة",
            "",
            conclusion,
        ]
    )
    return "\n".join(parts).rstrip() + "\n"


def _strip_ids_from_report_markdown(md: str) -> str:
    """Drop '(IDS)' after the forensic report title (any heading level or inline)."""
    if not isinstance(md, str) or not md.strip():
        return md
    md = re.sub(
        r"^(#+)\s*التقرير الجنائي الرقمي\s*\(\s*IDS\s*\)",
        r"\1 التقرير الجنائي الرقمي",
        md,
        flags=re.MULTILINE,
    )
    return re.sub(
        r"التقرير الجنائي الرقمي\s*\(\s*IDS\s*\)",
        "التقرير الجنائي الرقمي",
        md,
    )


def _investigator_report_section_md(name: str) -> str:
    """Arabic «معلومات المحقق» under the main report heading — تم الرفع بواسطة المحقق + الاسم."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return (
        "## معلومات المحقق\n\n"
        f"تم الرفع بواسطة المحقق **{name}**.\n\n"
        f"**تاريخ إعداد التقرير:** {ts}\n"
    )


def _inject_investigator_into_markdown(md: str, investigator_name: str | None) -> str:
    """Insert «معلومات المحقق» immediately under the forensic report title."""
    if not investigator_name or not str(investigator_name).strip():
        return md
    name = str(investigator_name).strip()
    block = _investigator_report_section_md(name)
    if not isinstance(md, str):
        return f"# التقرير الجنائي الرقمي\n\n{block}"
    text = md.lstrip("\ufeff").rstrip()
    if not text:
        return f"# التقرير الجنائي الرقمي\n\n{block}"
    lines = text.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") and "التقرير الجنائي" in stripped:
            return "\n".join(lines[: i + 1] + ["", block.rstrip(), ""] + lines[i + 1 :])
    return f"{block}\n\n{text}\n"


def _dynamic_recommendations_from_evidence(
    events: list[dict[str, str]],
    row_evidence: list[dict[str, Any]] | None = None,
    malicious_rate: float = 0.0,
) -> list[str]:
    row_evidence = row_evidence or []
    tids: list[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        tids.extend(_extract_technique_ids(str(ev.get("mitre", ""))))
    tid_set = {t.upper() for t in tids}

    tags = {t for e in row_evidence for t in (e.get("context_tags") or [])}
    recs: list[str] = []

    if "T1200" in tid_set or "T0847" in tid_set or "usb_or_removable_context" in tags:
        recs.append(
            "تفعيل سياسة التحكم بوسائط USB (Allow-list) وعزل الأجهزة التي ظهر عليها إدراج وسائط خارجية أثناء الحادث."
        )
    if "T1204" in tid_set or "T1059" in tid_set or "T1059.001" in tid_set:
        recs.append(
            "منع تنفيذ الملفات والسكريبتات غير الموقعة من المسارات القابلة للإزالة، ومراجعة سجلات PowerShell/CommandLine."
        )
    if "T1060" in tid_set or "T1547" in tid_set:
        recs.append(
            "فحص مفاتيح Run/Startup والخدمات المجدولة لإزالة آليات الاستمرارية واستعادة إعدادات الإقلاع الآمن."
        )
    if "T1562" in tid_set or "TA0107" in { _technique_to_ics_tactic_id(t) for t in tid_set }:
        recs.append(
            "التحقق من تعطيل/تلاعب أدوات الحماية (AV/EDR/IDS) وإرجاع السياسات القسرية عبر GPO أو منصة الإدارة المركزية."
        )
    if "T1021" in tid_set or "T1021.001" in tid_set or "T1021.002" in tid_set:
        recs.append(
            "تقييد RDP/SMB بين مناطق OT، وتطبيق وصول أقل صلاحية مع مراقبة محاولات الحركة الجانبية داخل شبكة SCADA."
        )
    if "T1071" in tid_set or "T1071.001" in tid_set:
        recs.append(
            "تحليل الاتصالات الخارجية HTTPS المشبوهة (SNI/JA3/Domain/IP) وحجب قنوات C2 على الجدار الناري وProxy."
        )
    if "T1567" in tid_set or "T1041" in tid_set or "T1213" in tid_set:
        recs.append(
            "مراجعة حركة رفع البيانات للخارج وتفعيل DLP/egress filtering لمنع التسريب من محطات HMI/Engineering."
        )
    if "T0831" in tid_set or "T0830" in tid_set or "elevated_scada_command_pattern" in tags:
        recs.append(
            "تدقيق أوامر PLC/SCADA خلال نافذة الحادث ومقارنتها بخط الأساس التشغيلي قبل إعادة أي أوامر تحكم للإنتاج."
        )

    if malicious_rate >= 0.85:
        recs.append("رفع مستوى الاستجابة إلى احتواء فوري (SEV-1) مع إخطار فريق OT وIR وتجميد التغييرات غير الحرجة.")
    elif malicious_rate >= 0.55:
        recs.append("تنفيذ احتواء موجّه للأصول المتأثرة ومراقبة فورية لمدة 24 ساعة مع توسيع جمع السجلات.")

    # Stable defaults when signals are sparse.
    if not recs:
        recs = [
            "عزل الجهاز المتأثر فوراً عن شبكات OT وIT.",
            "حجب عناوين IP المشبوهة على الجدار الناري وأنظمة IDS.",
            "مراجعة أوامر PLC وSCADA خلال نافذة زمن الحادث.",
            "إعادة تعيين كلمات المرور الحساسة وتفعيل المصادقة متعددة العوامل.",
            "حفظ الأدلة الرقمية وأخذ نسخة من حركة الشبكة للتحقيق الجنائي.",
        ]

    # Dedupe while preserving order.
    out: list[str] = []
    seen: set[str] = set()
    for r in recs:
        k = " ".join(str(r).split())
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out[:8]


def _dynamic_final_report_from_evidence(
    summary: dict[str, Any],
    events: list[dict[str, str]],
    row_evidence: list[dict[str, Any]] | None = None,
) -> str:
    row_evidence = row_evidence or []
    total = int(summary.get("total_records") or 0)
    mal = int(summary.get("malicious_count") or 0)
    rate = float(summary.get("malicious_rate") or 0.0)
    avg = float(summary.get("average_malicious_probability") or 0.0)
    mode = str(summary.get("inference_mode") or "unknown")
    hyp = str(summary.get("primary_attack_hypothesis") or "").strip()

    tids: list[str] = []
    for ev in events:
        if isinstance(ev, dict):
            tids.extend(_extract_technique_ids(str(ev.get("mitre", ""))))
    tids = list(dict.fromkeys([t.upper() for t in tids]))[:6]

    tactics_ar: list[str] = []
    for tid in tids:
        _, tac_ar = _tactic_meta_for_technique(tid)
        if tac_ar not in tactics_ar:
            tactics_ar.append(tac_ar)
    tactics_txt = " ← ".join(tactics_ar[:6]) if tactics_ar else "غير كافٍ لاشتقاق مسار تكتيكي كامل"
    tids_txt = "، ".join(tids) if tids else "لا توجد معرفات تقنية مؤكدة"

    tags = {t for e in row_evidence for t in (e.get("context_tags") or [])}
    tags_txt = "، ".join(sorted(tags)) if tags else "لا توجد وسوم سياقية إضافية"

    hyp_line = (
        f"الفرضية السلوكية الأبرز: {hyp}."
        if hyp
        else "الفرضية السلوكية الأبرز: غير محدد — راجع احتمالات النموذج والحقول."
    )
    return (
        f"التحليل الحالي للملف يُظهر {mal} سجلًا عالي الاشتباه من أصل {total} "
        f"(نسبة خبث {rate*100:.2f}%، ومتوسط احتمال {avg*100:.2f}%) بنمط استدلال {mode}. "
        f"المسار المُستنتج من الأدلة يتضمن التكتيكات: {tactics_txt}. "
        f"أبرز التقنيات المرصودة: {tids_txt}. "
        f"الوسوم السياقية: {tags_txt}. "
        f"{hyp_line}"
    ).strip()


def _looks_generic_final_report(text: str) -> bool:
    s = " ".join(str(text or "").split())
    if not s or len(s) < 40:
        return True
    generic_needles = (
        "يوصى بالاحتواء",
        "مستوى خطورة الحادث",
        "حفظ الأدلة الرقمية",
    )
    has_number = bool(re.search(r"\d", s))
    return (not has_number) or any(n in s for n in generic_needles)


def _fallback_report(
    events: list[dict[str, str]],
    malicious_rate: float,
    summary: dict[str, Any] | None = None,
    row_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    severity = "عالية" if malicious_rate > 0.35 else "متوسطة" if malicious_rate > 0.1 else "منخفضة"
    recs = _dynamic_recommendations_from_evidence(events, row_evidence, malicious_rate)
    summary_obj = dict(summary or {})
    summary_obj.setdefault("malicious_rate", malicious_rate)
    final_dynamic = _dynamic_final_report_from_evidence(summary_obj, events, row_evidence)
    return {
        "timeline": events,
        "recommendations": recs,
        "final_report": (
            f"{final_dynamic} "
            f"تصنيف الشدة الإجمالي: {severity}."
        ).strip(),
    }


def _gemini_enrich(
    base_report: dict[str, Any],
    summary: dict[str, Any],
    top_suspicious_rows: list[dict[str, Any]],
    row_evidence: list[dict[str, Any]] | None = None,
    investigator_name: str | None = None,
) -> dict[str, Any]:
    row_evidence = row_evidence or []
    guide_excerpt = _mitre_guide_excerpt(9500)

    base_timeline_ref: list[dict[str, Any]] = [
        dict(x) for x in (base_report.get("timeline") or []) if isinstance(x, dict)
    ]
    analysis_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "source_file": summary.get("source_file"),
                "total_records": summary.get("total_records"),
                "malicious_rate": round(float(summary.get("malicious_rate", 0)), 5),
                "primary_hypothesis": str(summary.get("primary_attack_hypothesis") or ""),
                "timeline_slice": base_timeline_ref[:12],
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8", errors="ignore"),
    ).hexdigest()[:20]

    def _is_explicit_mitre_timeline(tl: list[dict[str, Any]]) -> bool:
        if not isinstance(tl, list) or len(tl) < 4:
            return False
        with_tid = 0
        for item in tl:
            if not isinstance(item, dict):
                continue
            if _extract_technique_ids(str(item.get("mitre", ""))):
                with_tid += 1
        return with_tid >= max(4, int(len(tl) * 0.6))

    explicit_timeline_mode = _is_explicit_mitre_timeline(base_timeline_ref)

    def _pack_result(
        timeline: list[Any],
        recommendations: list[Any],
        final_summary: str,
        raw_mitre: Any,
        *,
        gemini_mitre_used: bool = False,
    ) -> dict[str, Any]:
        merged_timeline = _merge_timeline_prefer_arabic_evidence(
            timeline if isinstance(timeline, list) else [],
            base_timeline_ref,
        )
        rec_in = [str(r).strip() for r in (recommendations or []) if str(r).strip()]
        rec_dyn = _dynamic_recommendations_from_evidence(
            merged_timeline,
            row_evidence,
            float(summary.get("malicious_rate", 0)),
        )
        rec_merged: list[str] = []
        seen_recs: set[str] = set()
        for r in rec_in + rec_dyn:
            key = " ".join(str(r).split())
            if not key or key in seen_recs:
                continue
            seen_recs.add(key)
            rec_merged.append(key)
        if not rec_merged:
            rec_merged = rec_dyn[:]
        final_summary_text = (
            str(final_summary).strip()
            if isinstance(final_summary, str)
            else ""
        )
        dynamic_summary = _dynamic_final_report_from_evidence(
            summary, merged_timeline, row_evidence
        )
        if _looks_generic_final_report(final_summary_text):
            final_summary_text = dynamic_summary
        final_summary_text = _ensure_final_report_has_severity(
            final_summary_text, float(summary.get("malicious_rate", 0))
        )
        # Markdown is assembled only from merged pipeline outputs (never model-freeform text)
        # so numbers and sections always match timeline/recommendations/summary.
        md = _build_fallback_markdown(
            summary=summary,
            timeline=merged_timeline,
            recommendations=rec_merged,
            final_report=final_summary_text,
            top_suspicious_rows=top_suspicious_rows,
            suspicious_findings=None,
        )
        md = _strip_ids_from_report_markdown(md)
        mitre_map = _normalize_mitre_attack_map(
            raw_mitre, merged_timeline, summary, row_evidence
        )
        if isinstance(mitre_map, dict):
            stages_list = mitre_map.get("stages") or []
            tac_ids: list[str] = []
            for st in stages_list:
                if isinstance(st, dict) and st.get("tactic_id"):
                    tac_ids.append(str(st["tactic_id"]))
            mitre_map = {
                **mitre_map,
                "_meta": {
                    "analysis_fingerprint": analysis_fingerprint,
                    "enrichment_source": (
                        "gemini" if gemini_mitre_used else "heuristic_and_rules"
                    ),
                    "distinct_tactic_stages": len(set(tac_ids)),
                    "ics_matrix": "https://attack.mitre.org/matrices/ics/",
                    "note_en": (
                        "Stages follow ATT&CK for ICS (TA01xx) from this file’s evidence. "
                        "Phases such as Persistence or Privilege Escalation appear only when "
                        "techniques/evidence support them—not every upload traverses all tactics."
                    ),
                },
            }
        return {
            "timeline": merged_timeline,
            "recommendations": rec_merged[:8],
            "final_report": final_summary_text,
            "markdown_report": md,
            "mitre_attack_map": mitre_map,
        }

    api_key = _gemini_api_key()
    if not api_key:
        fallback = _fallback_report(
            base_report["timeline"],
            float(summary.get("malicious_rate", 0)),
            summary,
            row_evidence,
        )
        return _pack_result(
            fallback["timeline"],
            fallback["recommendations"],
            fallback["final_report"],
            None,
            gemini_mitre_used=False,
        )

    inv_ctx = ""
    inv_st = (investigator_name or "").strip()
    if inv_st:
        inv_ctx = (
            f"سياق الطلب: المحقق المسؤول عن رفع الدليل هو «{inv_st}». "
            "أبرز هذا الاسم باختصار في narrative_ar أو في فقرة final_report بشكل طبيعي. "
            "لا تنشئ عنواناً منفصلاً باسم «معلومات المحقق» لأنه يُضاف آلياً لاحقاً.\n\n"
        )

    schema_hint = (
        '"mitre_attack_map": {\n'
        '  "narrative_ar": "ملخص مسار الهجوم للمحقق",\n'
        '  "stages": [\n'
        "    {\n"
        '      "order": 1,\n'
        '      "tactic_id": "TA0108",\n'
        '      "tactic_ar": "اسم التكتيك بالعربية",\n'
        '      "nodes": [\n'
        "        {\n"
        '          "technique_id": "Txxxx",\n'
        '          "name_ar": "وصف التقنية",\n'
        '          "name_en": "optional English",\n'
        '          "evidence_ar": "ربط صريح بأدلة من التحليل؛ إن وُجدت تقنيات إضافية اذكرها هنا نصاً",\n'
        '          "time": "من الحدث إن وُجد"\n'
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}"
    )
    prompt = (
        f"{inv_ctx}"
        "أنت محلل أمن سيبراني OT/ICS وخبير MITRE ATT&CK. أعد JSON صارم بالمفاتيح فقط: "
        "timeline, recommendations, final_report, mitre_attack_map.\n"
        "لا تُرجع markdown_report — يُجمَّع تقرير Markdown على الخادم من هذه الحقول ومن summary حتى تطابق الأرقام والأقسام دائماً.\n"
        "- timeline: مصفوفة عناصر فيها time, title (عربي), mitre (مثل MITRE: Txxxx), detail (عربي). "
        "رتّب الأحداث زمنياً تصاعدياً؛ استخدم أوقاتاً منطقية من row_evidence (event_time_display) أو من "
        "البيانات الأصلية، ولا تستخدم Flow Duration كوقت تقويمي.\n"
        "- recommendations: نصوص عربية عملية.\n"
        "- final_report: فقرة عربية مختصرة تلخّص المسار والشدة وتتوافق عددياً مع summary؛ "
        "إن وُجد اسم المحقق في السياق أعلاه، أذكره بجملة طبيعية. "
        "لا تُكرر جداول الملخص؛ سيتم إضافة «تصنيف الشدة الإجمالي» على الخادم إن غاب.\n"
        "- mitre_attack_map: خريطة مراحل هجوم متسلسلة مرتبطة بالأدلة، بنية كالتالي:\n"
        f"{schema_hint}\n"
        "التزم بماتريكس MITRE ATT&CK للأنظمة الصناعية (ICS): "
        "https://attack.mitre.org/matrices/ics/ — tactic_id يجب أن يكون من معرفات TA01xx التالية "
        f"بهذا الترتيب عند بناء المراحل: {', '.join(_ICS_TACTIC_ORDER)}. "
        "name_ar لكل تكتيك يطابق أسماء ICS (مثال: TA0108 الوصول الأولي). "
        "رتّب stages بحيث تعكس تقدماً منطقياً في سلسلة ICS (قد لا تظهر كل التكتيكات). "
        "أولوية للتقنيات T08xx عند ربط أحداث OT/ICS.\n"
        "مهم: لكل مرحلة (stage) عقدة nodes واحدة فقط؛ لا تكرر نفس العنوان أو نفس الوقت في عقد متعددة. "
        "إذا احتجت أكثر من تقنية، ضع technique_id الأهم في العقدة واذكر الباقي داخل evidence_ar.\n"
        "التزم بتعريفات التقنيات كما في https://attack.mitre.org/techniques/ics/؛ لا تخترع أرقاماً غير موجودة. "
        "إذا غابت التفاصيل في البيانات، قل ذلك في evidence_ar وخفّض الثقة اللفظية.\n"
        "التزم عددياً بحقول ملخص التنبؤات (summary): primary_attack_hypothesis، attack_family_profile، "
        "dataset_label_distribution إن وُجدت، وfeature_importance_top، وinference_mode. "
        "لا تُعارض احتمالات XGBoost أو نسب الخبث؛ اربط MITRE بهذه الحقائق.\n"
        f"معرّف هذا التحليل (للتمييز بين ملفات مختلفة — استخدمه في صياغة narrative_ar وربط الأدلة): {analysis_fingerprint}\n"
        "مهم جداً: لا تنسخ نفس النص الشبه ثابت بين تحليلات مختلفة؛ اذكر أرقاماً/أوقاتاً/عناوين أعمدة من JSON أدناه. "
        "إذا لم تُظهر الأدلة مرحلة معيّنة (مثل الاستمرارية Persistence أو تصعيد الصلاحيات)، لا تُنشئ مرحلة وهمية؛ "
        "اذكر في narrative_ar أن هذه التكتيكات غير مُستندة للبيانات الحالية.\n"
        "حاول تنويع tactic_id بين المراحل عندما تدعم الأدلة تقنيات مرتبطة بتكتيكات مختلفة؛ "
        "إن بقيت كل الأدلة ضمن نفس التكتيك (مثلاً وصول أولي متكرر) فاصرح بذلك بدل اختلاق مسار كامل.\n\n"
        f"أدلة مُستخرجة لأشد السجلات (row_evidence): {json.dumps(row_evidence[:8], ensure_ascii=False)}\n"
        f"ملخص التنبؤات: {json.dumps(summary, ensure_ascii=False)}\n"
        f"أعلى السجلات المشبوهة: {json.dumps(top_suspicious_rows, ensure_ascii=False)}\n"
        f"الأحداث الأساسية: {json.dumps(base_report['timeline'], ensure_ascii=False)}\n"
        f"التوصيات الأساسية: {json.dumps(base_report['recommendations'], ensure_ascii=False)}\n"
        f"الخلاصة الأساسية: {base_report['final_report']}\n\n"
        f"--- اقتباس من دليل MITRE (مرجع تصنيف) ---\n{guide_excerpt}\n"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.32, "topP": 0.9, "maxOutputTokens": 4096},
    }
    try:
        response = requests.post(
            f"{GEMINI_ENDPOINT}?key={api_key}",
            json=payload,
            timeout=90,
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise ValueError("empty candidates")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(
            str(p.get("text", "")) for p in parts if isinstance(p, dict)
        )
        parsed = _extract_json(text)
        if isinstance(parsed, dict):
            final_timeline = parsed.get("timeline", base_report["timeline"])
            final_recommendations = parsed.get(
                "recommendations", base_report["recommendations"]
            )
            final_summary = parsed.get("final_report", base_report["final_report"])
            raw_mitre = parsed.get("mitre_attack_map")
            if explicit_timeline_mode:
                st = raw_mitre.get("stages") if isinstance(raw_mitre, dict) else None
                stage_count = len(st) if isinstance(st, list) else 0
                # For MITRE-labeled log datasets, prefer deterministic server mapping
                # when Gemini returns too few/flat stages.
                if stage_count < max(5, len(base_timeline_ref) // 2):
                    raw_mitre = None
            gemini_mitre_ok = isinstance(raw_mitre, dict) and bool(
                raw_mitre.get("stages")
            )
            return _pack_result(
                final_timeline,
                final_recommendations,
                final_summary,
                raw_mitre,
                gemini_mitre_used=gemini_mitre_ok,
            )
    except Exception:
        pass

    fallback = _fallback_report(
        base_report["timeline"],
        float(summary.get("malicious_rate", 0)),
        summary,
        row_evidence,
    )
    return _pack_result(
        fallback["timeline"],
        fallback["recommendations"],
        fallback["final_report"],
        None,
        gemini_mitre_used=False,
    )


def _attack_sequence_ar_from_evidence(ev: dict[str, Any]) -> str:
    """Short MITRE-oriented attack path hint for this row (Arabic)."""
    tags = set(ev.get("context_tags") or [])
    if "usb_or_removable_context" in tags:
        return (
            "① إرفاق وسيط تخزين/USB (T0847 / Initial Access) ← "
            "② تنفيذ أو نقل عبر الوسيط ← "
            "③ اتصال تطبيقي محتمل للقيادة أو المزامنة (T1071) عند إثبات جلسة لاحقة."
        )
    if "elevated_scada_command_pattern" in tags:
        return (
            "① تعرّض/وصول لبيئة ICS ← "
            "② أوامر تحكم غير متماثلة مع الخط الأساسي (T0855) ← "
            "③ تعديل مهام/منطق تحكم (T0831) إن ثبتت كتابة أو جدولة."
        )
    if "handshake_stress_pattern" in tags:
        return (
            "① استكشاف خدمات أو ضغط مصافحة TCP (T1046) ← "
            "② قناة قيادة عبر بروتوكول طبقة تطبيقات (T1071) ← "
            "③ تصعيد أو حركة جانبية حسب بقية السجلات."
        )
    return (
        "① سلوك تدفق شبكي شاذ (مؤشرات عددية) ← "
        "② استكشاف/مسح أو C2 محتمل (T1046 / T1071) ← "
        "③ مطابقة مع EDR/SIEM لتحديد المسار الكامل."
    )


def _fallback_narrative_from_evidence(ev: dict[str, Any], malicious_rate: float) -> dict[str, str]:
    """Arabic + concise English hints from measured row evidence (no LLM)."""
    rid = ev.get("row_index", "?")
    ev_time = ev.get("event_time_display") or ""
    dlabel = ev.get("dataset_label") or ""
    label_note = f" تصنيف الدليل: {dlabel}." if dlabel else ""
    time_note = f" وقت الحدث: {ev_time}." if ev_time else ""
    tags = ev.get("context_tags") or []
    devs = ev.get("top_deviations") or []
    top_names = [d["column"] for d in devs[:4]]
    bullets = ev.get("evidence_bullets") or []
    km = ev.get("key_metrics") or {}
    fams = ev.get("inferred_attack_families") or {}
    fam_hint = ""
    if isinstance(fams, dict) and fams:
        top_f = max(fams.items(), key=lambda x: float(x[1]) if x[1] is not None else 0)
        fam_hint = f" فرضية سلوكية للتدفق: {top_f[0]}."

    if "usb_or_removable_context" in tags:
        suspected = (
            f"【سجل #{rid}】ارتباط قوي بإشارة تفاعل تخزين خارجي/USB؛ "
            f"I/O خارجي≈{km.get('External_Device_IO_Rate', '—')}.{time_note}{label_note}{fam_hint}"
        )
        nxt = (
            "اعزل الجهاز المذكور في السجلات، واحتفظ بسجل الأجهزة USB، "
            "وراجع التعريفات الفورية (PnP) وسلسلة التثبيت للبرامج بعد الإدراج."
        )
    elif "elevated_scada_command_pattern" in tags:
        suspected = (
            f"【سجل #{rid}】نمط أوامر/تحكم صناعي مرتفع مقارنة ببقية العيّنة؛ يلزم ربطه بمحطة HMI/PLC."
            f"{time_note}{label_note}{fam_hint}"
        )
        nxt = (
            "قارن مع baseline تشغيل طبيعي، وراجع سجلات البروتوكولات الصناعية، "
            "والجداول الزمنية لأي صيانة مجدولة."
        )
    elif "handshake_stress_pattern" in tags:
        suspected = (
            f"【سجل #{rid}】ضغط على مصافحة TCP (SYN/RST) يشير لمسح منافذ أو اضطراب اتصال."
            f"{time_note}{label_note}{fam_hint}"
        )
        nxt = (
            "اطلب من فريق الشبكة لقطة للجلسات نحو نفس الوجهة، "
            "وتدقيق جدار الحماية/NIDS على نفس الفترة الزمنية."
        )
    else:
        suspected = (
            f"【سجل #{rid}】تدفق شبكي شاذ؛ أبرز الحقول: "
            + ("، ".join(top_names) if top_names else "عدة مؤشرات رقمية")
            + f".{time_note}{label_note}{fam_hint}"
        )
        nxt = (
            "صِغ استعلاماً في SIEM يقيّد نفس الوجهة/المنفذ والزمن، "
            "ثم اربط بنتائج EDR إن وُجدت."
        )

    why_parts = [f"معرف السجل {rid}؛ احتمال النموذج={float(ev.get('risk_score', 0)):.4f}."]
    for d in devs[:4]:
        why_parts.append(
            f"{d['column']}={d['value']} (Z={d['z_score']:+.1f})"
        )
    why = (
        " ".join(why_parts)
        if len(why_parts) > 1
        else f"سجل #{rid}: احتمال خبث من النموذج مع نقص تفاصيل أعمدة رقمية."
    )

    if "handshake_stress_pattern" in tags:
        family = (
            "قد يتوافق سلوكياً مع مسح/إرهاق اتصال أو نشاط شبكي عدائي أولي؛ "
            "التصنيم الدقيق للعائلة يحتاج IOC وسجلات طرفية."
        )
    elif "usb_or_removable_context" in tags:
        family = (
            "غالباً مسار إساءة استخدام وسائط قابلة للإزالة أو أداة نقل ملفات؛ "
            "ليس بالضرورة عائلة برمجية واحدة."
        )
    else:
        family = (
            "سلوك شبكي شاذ قد يشبه برمجيات نقل بيانات أو C2 حسب بقية السجلات؛ "
            "لا يكفي لجزم عائلة دون مؤشرات إضافية."
        )

    zd = float(ev.get("risk_score", 0)) >= 0.96 and malicious_rate < 0.65
    if zd and len(devs) >= 4:
        zero = (
            "شذوذ متعدد الأبعاد مع انتشار محدود في العيّنة؛ مرشح لتحليل أعمق "
            "لاستبعاد/تأكيد صفر-يوم أو أداة مخصصة."
        )
    else:
        zero = (
            "لا دليل قوي من الأرقام وحدها على zero-day؛ يفضّل التحقق عبر sandbox وتوقيعات السلوك."
        )

    return {
        "suspected_process_or_file": suspected,
        "why_malicious": why,
        "malware_family_assessment": family,
        "zero_day_assessment": zero,
        "investigator_next_step": nxt,
        "attack_sequence_ar": _attack_sequence_ar_from_evidence(ev),
        "evidence_points": bullets[:5],
    }


def _build_fallback_suspicious_analysis(
    top_suspicious_rows: list[dict[str, Any]],
    malicious_rate: float,
    row_evidence: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    findings = []
    ev_by_row = {int(e["row_index"]): e for e in (row_evidence or [])}
    for idx, item in enumerate(top_suspicious_rows, start=1):
        score = float(item.get("score", 0.0))
        rid = int(item.get("row_index", -1))
        ev = ev_by_row.get(rid) or {"row_index": rid, "risk_score": score}
        nar = _fallback_narrative_from_evidence(ev, malicious_rate)
        findings.append(
            {
                "row_index": rid,
                "risk_score": score,
                "suspected_process_or_file": nar["suspected_process_or_file"],
                "why_malicious": nar["why_malicious"],
                "malware_family_assessment": nar["malware_family_assessment"],
                "zero_day_assessment": nar["zero_day_assessment"],
                "investigator_next_step": nar["investigator_next_step"],
                "attack_sequence_ar": nar.get("attack_sequence_ar") or "",
                "priority": _priority_from_score(score),
                "confidence": min(0.99, max(0.55, score)),
                "rank": idx,
                "evidence_points": nar.get("evidence_points") or [],
            }
        )
    _uniquify_suspicious_findings_rows(findings, row_evidence or [], malicious_rate)
    return findings


def _merge_gemini_findings_with_evidence(
    gemini_rows: list[dict[str, Any]],
    row_evidence: list[dict[str, Any]],
    malicious_rate: float,
    top_suspicious_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep numeric identity from our data; take Gemini text when present."""
    by_rid: dict[int, dict[str, Any]] = {}
    for item in gemini_rows:
        try:
            rid = int(item.get("row_index", -1))
        except (TypeError, ValueError):
            continue
        if rid >= 0:
            by_rid[rid] = item

    merged: list[dict[str, Any]] = []
    for idx, ev in enumerate(row_evidence, start=1):
        rid = int(ev["row_index"])
        score = float(ev.get("risk_score", 0.0))
        g = by_rid.get(rid)
        if g is None and idx <= len(gemini_rows):
            g = gemini_rows[idx - 1]
        fb = _fallback_narrative_from_evidence(ev, malicious_rate)
        if not g:
            merged.append(
                {
                    "row_index": rid,
                    "risk_score": score,
                    "suspected_process_or_file": fb["suspected_process_or_file"],
                    "why_malicious": fb["why_malicious"],
                    "malware_family_assessment": fb["malware_family_assessment"],
                    "zero_day_assessment": fb["zero_day_assessment"],
                    "investigator_next_step": fb["investigator_next_step"],
                    "attack_sequence_ar": fb.get("attack_sequence_ar") or "",
                    "priority": _priority_from_score(score),
                    "confidence": min(0.99, max(0.55, score)),
                    "rank": idx,
                    "evidence_points": fb.get("evidence_points") or [],
                }
            )
            continue

        def _g_str(key: str, fallback: str) -> str:
            v = g.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
            return fallback

        pts = g.get("evidence_points")
        if not isinstance(pts, list) or not pts:
            pts = fb.get("evidence_points") or ev.get("evidence_bullets") or []

        merged.append(
            {
                "row_index": rid,
                "risk_score": score,
                "suspected_process_or_file": _g_str(
                    "suspected_process_or_file", fb["suspected_process_or_file"]
                ),
                "why_malicious": _g_str("why_malicious", fb["why_malicious"]),
                "malware_family_assessment": _g_str(
                    "malware_family_assessment", fb["malware_family_assessment"]
                ),
                "zero_day_assessment": _g_str(
                    "zero_day_assessment", fb["zero_day_assessment"]
                ),
                "investigator_next_step": _g_str(
                    "investigator_next_step", fb["investigator_next_step"]
                ),
                "attack_sequence_ar": _g_str(
                    "attack_sequence_ar", fb.get("attack_sequence_ar") or ""
                ),
                "priority": _g_str("priority", _priority_from_score(score)),
                "confidence": float(g.get("confidence") or min(0.99, max(0.55, score))),
                "rank": int(g.get("rank") or idx),
                "evidence_points": [str(p) for p in pts][:8],
            }
        )

    if not merged:
        return _build_fallback_suspicious_analysis(
            top_suspicious_rows, malicious_rate, row_evidence
        )
    _uniquify_suspicious_findings_rows(merged, row_evidence, malicious_rate)
    return merged[:5]


def _uniquify_suspicious_findings_rows(
    findings: list[dict[str, Any]],
    row_evidence: list[dict[str, Any]],
    malicious_rate: float,
) -> None:
    """If Gemini repeats the same text for multiple rows, swap in row-specific fallbacks."""
    ev_by = {int(e["row_index"]): e for e in row_evidence}

    def row_sig(f: dict[str, Any]) -> str:
        pts = f.get("evidence_points") or []
        pts_s = (
            "|".join(str(p) for p in pts[:6])
            if isinstance(pts, list)
            else ""
        )
        parts = (
            str(f.get("why_malicious", "")),
            str(f.get("suspected_process_or_file", "")),
            str(f.get("investigator_next_step", "")),
            str(f.get("malware_family_assessment", "")),
            str(f.get("zero_day_assessment", "")),
            pts_s,
        )
        return " ".join(" ".join(str(p).split()) for p in parts)[:650]

    buckets: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        buckets[row_sig(f)].append(i)
    for idxs in buckets.values():
        if len(idxs) <= 1:
            continue
        for i in idxs:
            f = findings[i]
            rid = int(f["row_index"])
            ev = ev_by.get(rid) or {
                "row_index": rid,
                "risk_score": float(f.get("risk_score", 0)),
            }
            fb = _fallback_narrative_from_evidence(ev, malicious_rate)
            f["why_malicious"] = fb["why_malicious"]
            f["suspected_process_or_file"] = fb["suspected_process_or_file"]
            f["investigator_next_step"] = fb["investigator_next_step"]
            f["malware_family_assessment"] = fb["malware_family_assessment"]
            f["zero_day_assessment"] = fb["zero_day_assessment"]
            f["attack_sequence_ar"] = fb.get("attack_sequence_ar") or ""
            if fb.get("evidence_points"):
                f["evidence_points"] = fb["evidence_points"]


def _gemini_suspicious_analysis(
    summary: dict[str, Any],
    top_suspicious_rows: list[dict[str, Any]],
    row_evidence: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    malicious_rate = float(summary.get("malicious_rate", 0))
    api_key = _gemini_api_key()
    if not api_key:
        return _build_fallback_suspicious_analysis(
            top_suspicious_rows, malicious_rate, row_evidence
        )

    system_text = (
        "أنت محلل DFIR لمنصة بَيّنة. ستتلقى أدلة رقمية مقاسة لكل سطر (قيم حقول، "
        "انحرافات معيارية، وسياقات مثل USB أو SCADA). "
        "أعد JSON صارم بالمفتاح findings فقط.\n"
        "قواعد:\n"
        "- findings: 3 إلى 5 عناصر، واحدة لكل عنصر في row_evidence بنفس ترتيب الإدخال.\n"
        "- row_index و risk_score يجب أن يطابقا القيم الواردة في كل عنصر من row_evidence.\n"
        "- لكل سجل: ابدأ suspected_process_or_file أو why_malicious بعبارة تحتوي رقم السجل صراحةً مثل "
        "\"سجل 37:\" أو \"【سجل 37】\" ثم محتوى مختلف عن باقي السجلات.\n"
        "- ممنوع نسخ نفس الفقرة أو نفس جملة why_malicious بين صفّين؛ إن تشابه نصان سيتم استبدالهما آلياً.\n"
        "- استخدم event_time_display و dataset_label و evidence_bullets و top_deviations من نفس عنصر row_evidence "
        "لتفريق السجلات.\n"
        "- الحقول النصية بالعربية، ومحددة لهذا السطر فقط: لا تكرر نفس الجمل بين السجلات.\n"
        "- استشهد بأسماء الأعمدة والأرقام من نفس عنصر row_evidence داخل why_malicious.\n"
        "- suspected_process_or_file: اذكر ما يمكن استنتاجه من الأعمدة (تدفق، USB، إلخ) "
        "وليس عبارة عامة.\n"
        "- investigator_next_step: خطوة عملية واحدة أو اثنتان مرتبطة بالمؤشرات المعطاة.\n"
        "- attack_sequence_ar: تسلسل هجوم مُقترح لهذا السطر فقط، بالعربية، "
        "مع ذكر تقنيات MITRE المناسبة (Txxxx) وأسهم ← بين المراحل.\n"
        "- evidence_points: مصفوفة 3-5 نصوص قصيرة بالعربية تلخص أدلة الرقم لذلك السطر.\n"
        "- التزم بحقول model_summary: primary_attack_hypothesis وattack_family_profile وfeature_importance_top "
        "وdataset_label_distribution عند صياغة التفسير؛ لا تُضخّم التهديد فوق ما تسمح به الأرقام.\n"
        "المفاتيح المطلوبة لكل عنصر: "
        "row_index, risk_score, suspected_process_or_file, why_malicious, "
        "malware_family_assessment, zero_day_assessment, investigator_next_step, "
        "attack_sequence_ar, priority, confidence, rank, evidence_points."
    )
    user_payload = {
        "model_summary": summary,
        "row_evidence": row_evidence,
    }
    prompt = json.dumps(user_payload, ensure_ascii=False)
    body = {
        "systemInstruction": {"parts": [{"text": system_text}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.22, "topP": 0.88, "maxOutputTokens": 3072},
    }
    try:
        response = requests.post(
            f"{GEMINI_ENDPOINT}?key={api_key}",
            json=body,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise ValueError("no candidates")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        text = "".join(texts)
        parsed = _extract_json(text)
        if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
            findings = [item for item in parsed["findings"] if isinstance(item, dict)]
            if findings:
                return _merge_gemini_findings_with_evidence(
                    findings, row_evidence, malicious_rate, top_suspicious_rows
                )
    except Exception:
        pass

    return _build_fallback_suspicious_analysis(
        top_suspicious_rows, malicious_rate, row_evidence
    )


def _build_chat_system_instruction(payload: ChatRecommendationRequest) -> str:
    mmap = payload.mitre_attack_map or {}
    mmap_compact: dict[str, Any] = {}
    if isinstance(mmap, dict) and mmap:
        mmap_compact["narrative_ar"] = mmap.get("narrative_ar")
        st = mmap.get("stages") or []
        if isinstance(st, list):
            mmap_compact["stages"] = [
                {
                    "tactic_ar": s.get("tactic_ar"),
                    "tactic_id": s.get("tactic_id"),
                    "techniques": [
                        n.get("technique_id")
                        for n in (s.get("nodes") or [])[:4]
                        if isinstance(n, dict)
                    ],
                }
                for s in st[:8]
                if isinstance(s, dict)
            ]
    ctx = {
        "analysis_summary": payload.analysis_summary or {},
        "recommendations": payload.recommendations or [],
        "timeline": payload.timeline or [],
        "suspicious_findings": (payload.suspicious_findings or [])[:5],
        "mitre_attack_map": mmap_compact or None,
    }
    ctx_json = json.dumps(ctx, ensure_ascii=False)
    return (
        "أنت منصة بَيّنة: مساعد تحقيق جنائي رقمي وDFIR لمحللي الأمن السيبراني.\n\n"
        "## قواعد إلزامية\n"
        "1) اللغة: العربية الفصحى الواضحة.\n"
        "2) ابدأ مباشرة بإجابة سؤال المستخدم؛ تجنّب المقدمات الفارغة مثل "
        "\"أستطيع مساعدتك\" أو \"مرحباً\" دون فائدة.\n"
        "3) عند وجود أرقام في سياق التحليل (معدل الخبث، عدد السجلات، احتمالية الهجوم)، "
        "اذكرها صراحة عندما تكون مرتبطة بالسؤال.\n"
        "4) للأسئلة الإجرائية: استخدم نقاطاً أو خطوات مرقمة قصيرة.\n"
        "5) إذا نقصت البيانات: اذكر ما الذي ينقص ثم ما الذي يجمعه المحقق (سجلات، أطر زمنية، أصول).\n"
        "6) لا تقدّم إرشادات هجومية أو استغلالاً؛ ركّز على الدفاع والتحقيق والاحتفاظ بالأدلة والاستجابة.\n"
        "7) إن كان السؤال عاماً (مثلاً كلمات المرور أو سياسات الحسابات)، "
        "أجب من منظور ممارسات المنظمات والتحقيق الآمن، مع ربطه بسياق الحالة إن وُجد.\n"
        "8) اعتبر حقول analysis_summary (مثل inference_mode، malicious_rate، primary_attack_hypothesis، "
        "attack_family_profile، feature_importance_top، dataset_label_distribution) حقائق مُلزمة؛ "
        "لا تتعارض معها واذكرها عند الإجابة عن أسئلة دقة التحليل.\n\n"
        "## سياق التحليل الحالي (JSON — استخدمه عند الصلة فقط)\n"
        f"{ctx_json}\n"
    )


def _chat_contents_from_history(payload: ChatRecommendationRequest) -> list[dict[str, Any]]:
    """Map UI history to Gemini multi-turn roles (user / model)."""
    contents: list[dict[str, Any]] = []
    for item in payload.history or []:
        raw_role = str(item.get("role", "user")).lower()
        content = (item.get("content") or "").strip()
        if not content:
            continue
        if raw_role in ("assistant", "model"):
            gemini_role = "model"
        else:
            gemini_role = "user"
        contents.append({"role": gemini_role, "parts": [{"text": content}]})

    if not contents:
        contents.append({"role": "user", "parts": [{"text": payload.question.strip()}]})
        return contents

    last = contents[-1]
    if last["role"] == "user" and last["parts"][0]["text"] != payload.question.strip():
        contents.append({"role": "user", "parts": [{"text": payload.question.strip()}]})
    elif last["role"] == "model":
        contents.append({"role": "user", "parts": [{"text": payload.question.strip()}]})

    return contents[-16:]


@app.post("/chat-recommendations")
def chat_recommendations(payload: ChatRecommendationRequest) -> dict[str, str]:
    api_key = _gemini_api_key()
    fallback_answer = _local_investigator_answer(payload.question)
    if not api_key:
        return {"answer": fallback_answer}

    system_instruction = _build_chat_system_instruction(payload)
    contents = _chat_contents_from_history(payload)
    body = {
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "contents": contents,
        "generationConfig": {
            "temperature": 0.35,
            "topP": 0.92,
            "maxOutputTokens": 2048,
        },
    }
    try:
        response = requests.post(
            f"{GEMINI_ENDPOINT}?key={api_key}",
            json=body,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            block = data.get("promptFeedback", {})
            reason = (block.get("blockReason") or "") if isinstance(block, dict) else ""
            if reason:
                return {
                    "answer": (
                        f"تعذر إكمال الرد تلقائياً ({reason}). جرّب إعادة صياغة السؤال بصيغة محايدة.\n\n"
                        f"{fallback_answer}"
                    )
                }
            return {"answer": fallback_answer}
        parts = (candidates[0].get("content") or {}).get("parts") or []
        texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        answer = "".join(texts).strip()
        return {"answer": answer or fallback_answer}
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 429:
            return {
                "answer": (
                    "تعذر استخدام Gemini حالياً بسبب تجاوز الحصة (Quota). "
                    "سيتم استخدام المساعد المحلي مؤقتاً:\n\n"
                    f"{fallback_answer}"
                )
            }
        return {"answer": fallback_answer}
    except Exception:
        return {"answer": fallback_answer}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


@app.get("/setup-status")
def setup_status() -> dict[str, Any]:
    return _setup_status()


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    investigator_name: str | None = Form(default=None),
) -> dict[str, Any]:
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    content = await file.read()
    inv_name = (investigator_name or "").strip() or None
    hashes = _calculate_hashes(content)
    try:
        df = pd.read_csv(StringIO(content.decode("utf-8", errors="ignore")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CSV file: {exc}") from exc

    setup = _setup_status()
    bootstrap_info = None
    inference_mode = "model"
    analysis_warnings: list[str] = []

    if not setup["ready"] and "Label" in df.columns:
        bootstrap_info = _bootstrap_artifacts_from_dataframe(df)
        setup = _setup_status()

    model_ref: xgb.XGBClassifier | None = None
    feature_columns_ref: list[str] | None = None

    if setup["ready"]:
        scaler = _load_scaler()
        model_ref = _load_model()
        feature_columns_ref = _resolve_feature_columns(scaler, model_ref)
        aligned_df, missing_cols = _align_columns_with_training_schema(
            df, feature_columns_ref
        )
        if missing_cols:
            for col in missing_cols:
                aligned_df[col] = 0.0
            sample = ", ".join(missing_cols[:10])
            more = "…" if len(missing_cols) > 10 else ""
            analysis_warnings.append(
                "أعمدة غير موجودة في CSV مُقارنةً بتدريب XGBoost؛ "
                f"عُيِّدت بصفر للاستدلال ({len(missing_cols)} عموداً). "
                f"أمثلة: {sample}{more}"
            )
        x_input = aligned_df[feature_columns_ref].copy()
        x_input = x_input.apply(pd.to_numeric, errors="coerce")
        x_input = x_input.replace([float("inf"), float("-inf")], pd.NA)
        null_cells_before_fill = int(x_input.isna().sum().sum())
        x_input = x_input.fillna(0.0)

        x_scaled = pd.DataFrame(
            scaler.transform(x_input),
            columns=feature_columns_ref,
            index=x_input.index,
        )
        probs = pd.Series(
            model_ref.predict_proba(x_scaled)[:, 1], index=x_scaled.index
        )
        inference_mode = "model"
    else:
        model_ref = None
        feature_columns_ref = None
        inference_mode = "heuristic"
        probs = _heuristic_probabilities(df)
        analysis_warnings.append(
            "ملفات النموذج غير متوفرة؛ يُستخدم الاستدلال الاستدلالي التقريبي."
        )
        null_cells_before_fill = int(
            df.select_dtypes(include=["number"])
            .replace([float("inf"), float("-inf")], pd.NA)
            .isna()
            .sum()
            .sum()
        )

    preds = (probs >= 0.5).astype(int)

    malicious_count = int(preds.sum())
    total = int(len(preds))
    malicious_rate = float(malicious_count / total) if total else 0.0
    avg_confidence = float(probs.mean()) if total else 0.0
    high_risk_count = int((probs >= 0.85).sum())

    top_order = probs.sort_values(ascending=False).head(5)
    top_suspicious_rows = [
        {"row_index": int(idx), "score": float(top_order.loc[idx])}
        for idx in top_order.index
    ]

    fi_top: list[dict[str, Any]] = []
    if model_ref is not None and feature_columns_ref:
        fi_top = _feature_importance_top(model_ref, feature_columns_ref, 12)

    label_dist: dict[str, int] | None = None
    gt_mix: dict[str, int] | None = None
    if "Label" in df.columns:
        vc = df["Label"].astype(str).str.strip().value_counts().head(12)
        label_dist = {str(k): int(v) for k, v in vc.items()}
        nb = vc[vc.index.str.lower() != "benign"]
        if not nb.empty:
            gt_mix = {str(k): int(v) for k, v in nb.head(6).items()}

    row_evidence_list = _build_row_evidence_list(df, top_suspicious_rows)
    primary_hyp, fam_profile = _aggregate_attack_profile(
        row_evidence_list, top_suspicious_rows
    )

    summary = {
        "total_records": total,
        "malicious_count": malicious_count,
        "malicious_rate": malicious_rate,
        "average_malicious_probability": avg_confidence,
        "high_risk_count": high_risk_count,
        "null_cells_filled": null_cells_before_fill,
        "inference_mode": inference_mode,
        "primary_attack_hypothesis": primary_hyp,
        "attack_family_profile": fam_profile,
        "feature_importance_top": fi_top,
        "dataset_label_distribution": label_dist,
        "ground_truth_attack_mix": gt_mix,
        "source_file": file.filename or "upload.csv",
    }

    timeline = _timeline_from_data(df, probs)
    base_report = _fallback_report(timeline, malicious_rate, summary, row_evidence_list)
    custody_chain = _build_custody_chain(
        file.filename or "evidence.csv",
        hashes,
        len(content),
        summary,
        inference_mode,
        inv_name,
    )

    # Bound wait so workers cannot hang indefinitely; keeps Vite/nginx proxies from returning 502.
    _enrich_deadline_s = 180
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_enrich = pool.submit(
                _gemini_enrich,
                base_report,
                summary,
                top_suspicious_rows,
                row_evidence_list,
                inv_name,
            )
            fut_susp = pool.submit(
                _gemini_suspicious_analysis,
                summary,
                top_suspicious_rows,
                row_evidence_list,
            )
            report = fut_enrich.result(timeout=_enrich_deadline_s)
            suspicious_findings = fut_susp.result(timeout=_enrich_deadline_s)
    except Exception:
        analysis_warnings.append(
            "تعذر إكمال إثراء التحليل (Gemini أو مهلة الانتظار)؛ عُرضت النتائج الأساسية والمسار الاحتياطي."
        )
        report = {
            "timeline": base_report["timeline"],
            "recommendations": base_report["recommendations"],
            "final_report": base_report["final_report"],
            "mitre_attack_map": _normalize_mitre_attack_map(
                None, base_report["timeline"], summary, row_evidence_list
            ),
        }
        suspicious_findings = _build_fallback_suspicious_analysis(
            top_suspicious_rows, malicious_rate, row_evidence_list
        )

    fr = _ensure_final_report_has_severity(
        str(report.get("final_report") or ""),
        float(summary.get("malicious_rate", 0)),
    )
    report["final_report"] = fr
    md_core = _build_fallback_markdown(
        summary=summary,
        timeline=report["timeline"],
        recommendations=report["recommendations"],
        final_report=fr,
        top_suspicious_rows=top_suspicious_rows,
        suspicious_findings=suspicious_findings,
    )
    md = _strip_ids_from_report_markdown(md_core.rstrip())
    md = _inject_investigator_into_markdown(md, inv_name)
    report["markdown_report"] = md + "\n\n" + _custody_chain_markdown(custody_chain)

    return {
        "summary": summary,
        "warnings": analysis_warnings,
        "hashes": hashes,
        "investigator_name": inv_name,
        "timeline": report["timeline"],
        "recommendations": report["recommendations"],
        "final_report": report["final_report"],
        "markdown_report": report["markdown_report"],
        "mitre_attack_map": report.get("mitre_attack_map"),
        "top_suspicious_rows": top_suspicious_rows,
        "suspicious_findings": suspicious_findings,
        "bootstrap": bootstrap_info,
        "custody_chain": custody_chain,
    }
