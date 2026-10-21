"""Orchestrates the six pipeline stages and persists the report record.

    01 Ingest -> 02 Extract -> 03 Contradict -> 04 Score -> 05 Calibrate -> 06 Report
"""
import json
import os
import time
import uuid

from . import contradictions, ml_model, scoring
from .extractor import NotAPEError, basic_file_info, extract_features
from .utils import utc_now_iso


def _new_id() -> str:
    return time.strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8]


def _iocs(features) -> dict:
    strs = features["strings"]["suspicious"]
    pick = lambda *types: sorted({s["value"] for s in strs if s["type"] in types})
    fi = features["file"]
    return {
        "hashes": {"SHA-256": fi["sha256"], "SHA-1": fi["sha1"], "MD5": fi["md5"],
                   "Imphash": features["pe"].get("imphash") or "-"},
        "network": pick("URL", "IPv4 address", "Hard-coded user agent"),
        "host": pick("Registry run key", "Registry path", "Staging path"),
        "commands": pick("Script / LOLBin command", "Shadow-copy / recovery tampering", "Log clearing"),
        "other": pick("Ransom / crypto-currency", "Long base64 blob"),
        "apis": [s for s in features["imports"]["suspicious"] if not s["context_only"]],
    }


def _summary(risk, ml, findings):
    level = risk["level"]
    cats = risk["categories_hit"]
    if not findings:
        return ("No PE contradictions were detected. The file's structure, imports and identity are "
                "consistent with ordinary compiled software. Static triage cannot rule out malicious "
                "behaviour that is only visible at run time.")
    top = findings[0]
    agree = (ml["calibrated_probability"] >= 0.5) == (risk["score"] >= 30)
    return (f"{len(findings)} contradiction(s) across {len(cats)} of 5 categories "
            f"({', '.join(cats)}). Strongest evidence: {top['name']} [{top['severity']}]. "
            f"Rule-based risk is {level} ({risk['score']}/100) and the calibrated model estimates a "
            f"{ml['reported_percent']}% malware probability - the two layers "
            + ("agree." if agree else "disagree, so manual review is recommended."))


def analyze_bytes(data: bytes, filename: str, cfg, source: str = "upload") -> dict:
    """Run the full static pipeline on in-memory bytes. Never executes anything."""
    t0 = time.perf_counter()
    report_id = _new_id()
    stages = []

    # 01 Ingest
    fi = basic_file_info(data, filename)
    stages.append({"stage": "Ingest", "detail": f"SHA-256 {fi['sha256'][:16]}..., {fi['size_human']}"})

    # 02 Extract
    try:
        features = extract_features(data, filename)
    except NotAPEError as exc:
        report = {
            "id": report_id, "valid_pe": False, "source": source, "demo": False,
            "analyzed_at": utc_now_iso(), "file": fi, "error": str(exc),
            "stages": stages + [{"stage": "Extract", "detail": "Rejected: not a valid PE image"}],
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        }
        save_report(report, cfg)
        return report
    return _finish(report_id, features, cfg, source, stages, t0)


def analyze_demo(cfg) -> dict:
    from .demo import demo_features
    t0 = time.perf_counter()
    features = demo_features()
    stages = [{"stage": "Ingest", "detail": "Illustrative feature record (no file)"}]
    return _finish(_new_id(), features, cfg, "demo", stages, t0)


def _finish(report_id, features, cfg, source, stages, t0):
    stages.append({"stage": "Extract", "detail": f"{len(features['sections'])} sections, "
                   f"{features['imports']['import_count']} imports, {features['strings']['total']} strings"})

    # 03 Contradict
    findings = contradictions.detect(features)
    notes = contradictions.context_notes(features)
    stages.append({"stage": "Contradict", "detail": f"{len(findings)} findings from 5 rule categories"})

    # 04 Score
    risk = scoring.compute_risk(findings)
    stages.append({"stage": "Score", "detail": f"{risk['points']} / {risk['max_points']} pts -> {risk['score']}"})

    # 05 Calibrate
    bundle = ml_model.load_model(cfg.MODEL_PATH, cfg.DATASET_PATH)
    vector = ml_model.vectorize(features, findings)
    ml = ml_model.predict(bundle, vector)
    stages.append({"stage": "Calibrate", "detail": f"RF {ml['raw_score']:.2f} -> calibrated {ml['calibrated_probability']:.2f}"})

    # 06 Report
    stages.append({"stage": "Report", "detail": f"Risk {risk['level']}, P(malware) {ml['reported_percent']}%"})
    report = {
        "id": report_id,
        "valid_pe": True,
        "source": source,
        "demo": bool(features.get("demo")),
        "synthetic_fixture": source == "synthetic",
        "analyzed_at": utc_now_iso(),
        "file": features["file"],
        "features": features,
        "findings": findings,
        "context_notes": notes,
        "risk": risk,
        "ml": ml,
        "iocs": _iocs(features),
        "summary": _summary(risk, ml, findings),
        "stages": stages,
        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
    }
    save_report(report, cfg)
    return report


def save_report(report, cfg):
    os.makedirs(cfg.REPORT_DIR, exist_ok=True)
    with open(os.path.join(cfg.REPORT_DIR, f"{report['id']}.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)


def load_report(report_id, cfg):
    if not report_id or any(c not in "0123456789abcdef-" for c in report_id):
        return None
    path = os.path.join(cfg.REPORT_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def list_reports(cfg, limit=8):
    if not os.path.isdir(cfg.REPORT_DIR):
        return []
    files = sorted((f for f in os.listdir(cfg.REPORT_DIR) if f.endswith(".json")),
                   key=lambda f: os.path.getmtime(os.path.join(cfg.REPORT_DIR, f)), reverse=True)
    out = []
    for f in files[:limit]:
        try:
            r = load_report(f[:-5], cfg)
        except Exception:
            continue
        if r:
            out.append({"id": r["id"], "name": r["file"]["name"], "valid_pe": r["valid_pe"],
                        "demo": r.get("demo"), "source": r.get("source"),
                        "score": r.get("risk", {}).get("score"), "level": r.get("risk", {}).get("level"),
                        "prob": r.get("ml", {}).get("reported_percent"), "at": r["analyzed_at"]})
    return out
