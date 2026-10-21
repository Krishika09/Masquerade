"""Stage 05 - Random Forest + probability calibration.

IMPORTANT - DEMO DATA
---------------------
No real malware corpus ships with this prototype. The model is trained on a
reproducible *synthetic* feature table (``data/demo_training_features.csv``)
generated from hand-written profiles of benign, benign-packed and malicious
PE feature distributions. It exists to demonstrate the full pipeline

    features -> Random Forest raw score -> CalibratedClassifierCV -> probability

end-to-end. Metrics computed on it describe the synthetic data only and say
nothing about real-world detection performance. Replace the CSV with features
extracted from a labelled corpus (same columns) and re-run
``python -m analyzer.ml_model`` to train a real model.

Split follows the project design: 70% train / 15% validation / 15% test.
The forest is fit on the training split only; the calibrator (Platt /
sigmoid, with isotonic reported for comparison) is fit on the validation
split; all reported metrics come from the untouched test split.
"""
import math
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split

from .contradictions import SEVERITY_FACTOR

try:  # scikit-learn >= 1.6
    from sklearn.frozen import FrozenEstimator
except ImportError:  # pragma: no cover
    FrozenEstimator = None

SEED = 42
N_SAMPLES = 4000

BASELINE_FEATURES = [
    "file_size_log10", "num_sections", "max_entropy", "mean_entropy", "overall_entropy",
    "imports_log", "dll_count", "strings_per_kb_log", "exports_log", "has_signature",
    "has_resources", "has_debug", "is_dll", "overlay_ratio", "suspicious_api_count",
]
CONTRADICTION_FEATURES = [
    "c_identity", "c_section", "c_high_entropy", "c_entropy_content", "c_api",
    "c_structural", "rwx_count", "ep_unusual", "n_findings",
]
ALL_FEATURES = BASELINE_FEATURES + CONTRADICTION_FEATURES

FEATURE_LABELS = {
    "file_size_log10": "File size (log10 bytes)", "num_sections": "Number of sections",
    "max_entropy": "Max section entropy", "mean_entropy": "Mean section entropy",
    "overall_entropy": "Whole-file entropy", "imports_log": "Imported APIs (log)",
    "dll_count": "Imported DLLs", "strings_per_kb_log": "Strings per KB (log)",
    "exports_log": "Exports (log)", "has_signature": "Has signature directory",
    "has_resources": "Has resources", "has_debug": "Has debug directory", "is_dll": "Is DLL",
    "overlay_ratio": "Overlay share of file", "suspicious_api_count": "Suspicious API count",
    "c_identity": "Contradiction: identity", "c_section": "Contradiction: section",
    "c_high_entropy": "Contradiction: high entropy",
    "c_entropy_content": "Contradiction: entropy-content", "c_api": "Contradiction: API",
    "c_structural": "Contradiction: structural", "rwx_count": "RWX section count",
    "ep_unusual": "Entry point outside code section", "n_findings": "Number of findings",
}


# --------------------------------------------------------------------------
# Feature vector shared by training data and live samples
# --------------------------------------------------------------------------

def vectorize(features: dict, findings: list) -> dict:
    pe, imp, strs, ent = features["pe"], features["imports"], features["strings"], features["entropy"]
    secs = features["sections"]
    bucket_sev = {}
    for f in findings:
        bucket_sev[f["bucket"]] = max(bucket_sev.get(f["bucket"], 0.0), SEVERITY_FACTOR[f["severity"]])
    ep_sec = pe.get("entry_section")
    return {
        "file_size_log10": round(math.log10(max(features["file"]["size"], 1)), 4),
        "num_sections": pe["number_of_sections"],
        "max_entropy": ent["max_non_resource"],
        "mean_entropy": ent["mean_section"],
        "overall_entropy": features["file"]["entropy"],
        "imports_log": round(math.log1p(imp["import_count"]), 4),
        "dll_count": imp["dll_count"],
        "strings_per_kb_log": round(math.log1p(strs["density_per_kb"]), 4),
        "exports_log": round(math.log1p(features["exports"]["count"]), 4),
        "has_signature": int(pe["has_signature"]),
        "has_resources": int(features["resources"]["count"] > 0),
        "has_debug": int(pe["has_debug"]),
        "is_dll": int(pe["is_dll"]),
        "overlay_ratio": features["overlay"]["ratio"] if not features["overlay"].get("is_signature") else 0.0,
        "suspicious_api_count": imp["suspicious_count"],
        "c_identity": bucket_sev.get("identity", 0.0),
        "c_section": bucket_sev.get("section", 0.0),
        "c_high_entropy": bucket_sev.get("high_entropy", 0.0),
        "c_entropy_content": bucket_sev.get("entropy_content", 0.0),
        "c_api": bucket_sev.get("api", 0.0),
        "c_structural": bucket_sev.get("structural", 0.0),
        "rwx_count": sum(1 for s in secs if s["writable"] and s["executable"]),
        "ep_unusual": int(bool(ep_sec) and ep_sec not in (".text", "CODE", ".code", ".textbss", "INIT", "PAGE")),
        "n_findings": len(findings),
    }


# --------------------------------------------------------------------------
# Synthetic, reproducible demo dataset
# --------------------------------------------------------------------------

def _pick(rng, table):
    """table: list of (probability, value); returns first hit or 0.0."""
    r = rng.random()
    acc = 0.0
    for p, v in table:
        acc += p
        if r < acc:
            return v
    return 0.0


def _row(rng, profile):
    U, N, B = rng.uniform, rng.normal, (lambda p: int(rng.random() < p))
    clip = lambda v, lo, hi: float(min(max(v, lo), hi))
    if profile == "benign_app":
        mx = clip(N(6.45, 0.3), 5.0, 7.25)
        r = dict(file_size_log10=clip(N(5.9, 0.6), 4.3, 8), num_sections=int(rng.integers(4, 9)),
                 max_entropy=mx, mean_entropy=clip(mx - U(0.8, 2.2), 2, 7),
                 overall_entropy=clip(N(6.0, 0.5), 3.5, 7.5),
                 imports_log=math.log1p(int(rng.lognormal(5.0, 0.8))), dll_count=int(rng.integers(3, 19)),
                 strings_per_kb_log=math.log1p(U(4, 25)), exports_log=math.log1p(B(0.3) * rng.integers(1, 400)),
                 has_signature=B(0.6), has_resources=B(0.9), has_debug=B(0.8), is_dll=B(0.3),
                 overlay_ratio=B(0.15) * U(0, 0.3), suspicious_api_count=int(rng.poisson(2.5)))
        c = dict(c_identity=_pick(rng, [(0.01, 0.3)]),
                 c_section=_pick(rng, [(0.02, 1.0), (0.06, 0.3)]),
                 c_high_entropy=_pick(rng, [(0.06, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.02, 0.6)]),
                 c_api=_pick(rng, [(0.02, 1.0), (0.05, 0.3)]),
                 c_structural=_pick(rng, [(0.03, 0.6), (0.15, 0.3)]), ep_unusual=B(0.03))
    elif profile == "benign_packed":
        r = dict(file_size_log10=clip(N(6.2, 0.6), 4.5, 8), num_sections=int(rng.integers(3, 6)),
                 max_entropy=U(7.2, 7.98), mean_entropy=U(5.5, 7.2), overall_entropy=U(7.0, 7.95),
                 imports_log=math.log1p(int(rng.integers(6, 41))), dll_count=int(rng.integers(2, 9)),
                 strings_per_kb_log=math.log1p(U(0.3, 4)), exports_log=0.0,
                 has_signature=B(0.35), has_resources=B(0.9), has_debug=B(0.2), is_dll=B(0.1),
                 overlay_ratio=B(0.5) * U(0.2, 0.9), suspicious_api_count=int(rng.poisson(3)))
        c = dict(c_identity=_pick(rng, [(0.01, 0.6)]),
                 c_section=_pick(rng, [(0.7, 1.0), (0.2, 0.6)]),
                 c_high_entropy=_pick(rng, [(0.8, 1.0), (0.2, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.7, 1.0), (0.2, 0.6)]),
                 c_api=_pick(rng, [(0.4, 0.3), (0.1, 0.6)]),
                 c_structural=_pick(rng, [(0.6, 0.6), (0.2, 0.3)]), ep_unusual=B(0.7))
    elif profile == "mal_packed":
        r = dict(file_size_log10=clip(N(5.4, 0.5), 4.0, 7.5), num_sections=int(rng.integers(3, 7)),
                 max_entropy=U(7.3, 7.99), mean_entropy=U(5.8, 7.6), overall_entropy=U(6.9, 7.98),
                 imports_log=math.log1p(int(rng.integers(2, 31))), dll_count=int(rng.integers(1, 7)),
                 strings_per_kb_log=math.log1p(U(0.1, 2.5)), exports_log=0.0,
                 has_signature=B(0.05), has_resources=B(0.5), has_debug=B(0.1), is_dll=B(0.15),
                 overlay_ratio=B(0.25) * U(0.1, 0.7), suspicious_api_count=int(rng.poisson(4)))
        c = dict(c_identity=_pick(rng, [(0.2, 1.0), (0.15, 0.6)]),
                 c_section=_pick(rng, [(0.75, 1.0), (0.15, 0.6)]),
                 c_high_entropy=_pick(rng, [(0.9, 1.0), (0.1, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.8, 1.0), (0.15, 0.6)]),
                 c_api=_pick(rng, [(0.25, 1.0), (0.5, 0.6), (0.15, 0.3)]),
                 c_structural=_pick(rng, [(0.6, 0.6), (0.3, 0.3)]), ep_unusual=B(0.75))
    elif profile == "mal_injector":
        mx = clip(N(6.4, 0.4), 5.0, 7.4)
        r = dict(file_size_log10=clip(N(5.1, 0.4), 4.0, 7), num_sections=int(rng.integers(4, 7)),
                 max_entropy=mx, mean_entropy=clip(mx - U(0.6, 1.8), 2, 7),
                 overall_entropy=clip(N(6.1, 0.4), 4, 7.6),
                 imports_log=math.log1p(int(rng.integers(20, 151))), dll_count=int(rng.integers(3, 10)),
                 strings_per_kb_log=math.log1p(U(2, 15)), exports_log=math.log1p(B(0.3) * rng.integers(1, 5)),
                 has_signature=B(0.03), has_resources=B(0.5), has_debug=B(0.3), is_dll=B(0.3),
                 overlay_ratio=B(0.1) * U(0, 0.3), suspicious_api_count=int(rng.poisson(8)))
        c = dict(c_identity=_pick(rng, [(0.15, 1.0), (0.1, 0.6)]),
                 c_section=_pick(rng, [(0.15, 1.0), (0.2, 0.3)]),
                 c_high_entropy=_pick(rng, [(0.1, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.05, 0.6)]),
                 c_api=_pick(rng, [(0.85, 1.0), (0.1, 0.6)]),
                 c_structural=_pick(rng, [(0.2, 0.6), (0.3, 0.3)]), ep_unusual=B(0.15))
    elif profile == "mal_masquerade":
        r = dict(file_size_log10=clip(N(5.3, 0.5), 4.0, 7.5), num_sections=int(rng.integers(3, 7)),
                 max_entropy=U(6.0, 7.6), mean_entropy=U(4.5, 6.8), overall_entropy=U(5.8, 7.8),
                 imports_log=math.log1p(int(rng.integers(15, 91))), dll_count=int(rng.integers(2, 9)),
                 strings_per_kb_log=math.log1p(U(1, 12)), exports_log=0.0,
                 has_signature=B(0.02), has_resources=B(0.7), has_debug=B(0.2), is_dll=B(0.05),
                 overlay_ratio=B(0.5) * U(0.2, 0.8), suspicious_api_count=int(rng.poisson(6)))
        c = dict(c_identity=_pick(rng, [(0.9, 1.0)]),
                 c_section=_pick(rng, [(0.15, 1.0), (0.3, 0.3)]),
                 c_high_entropy=_pick(rng, [(0.4, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.3, 0.6)]),
                 c_api=_pick(rng, [(0.6, 0.6), (0.1, 1.0)]),
                 c_structural=_pick(rng, [(0.4, 0.3)]), ep_unusual=B(0.3))
    else:  # mal_lowsignal: malware that looks benign statically (hard cases)
        mx = clip(N(6.5, 0.35), 5.0, 7.3)
        r = dict(file_size_log10=clip(N(5.6, 0.6), 4.2, 7.8), num_sections=int(rng.integers(4, 8)),
                 max_entropy=mx, mean_entropy=clip(mx - U(0.8, 2.0), 2, 7),
                 overall_entropy=clip(N(6.1, 0.5), 3.5, 7.6),
                 imports_log=math.log1p(int(rng.lognormal(4.5, 0.8))), dll_count=int(rng.integers(3, 14)),
                 strings_per_kb_log=math.log1p(U(3, 20)), exports_log=math.log1p(B(0.2) * rng.integers(1, 50)),
                 has_signature=B(0.08), has_resources=B(0.7), has_debug=B(0.4), is_dll=B(0.25),
                 overlay_ratio=B(0.2) * U(0, 0.4), suspicious_api_count=int(rng.poisson(4)))
        c = dict(c_identity=_pick(rng, [(0.1, 0.6)]),
                 c_section=_pick(rng, [(0.1, 0.3)]),
                 c_high_entropy=_pick(rng, [(0.1, 0.6)]),
                 c_entropy_content=_pick(rng, [(0.05, 0.6)]),
                 c_api=_pick(rng, [(0.25, 0.6), (0.1, 0.3)]),
                 c_structural=_pick(rng, [(0.25, 0.3)]), ep_unusual=B(0.1))
    r.update(c)
    r["rwx_count"] = int(c["c_section"] == 1.0) * int(rng.integers(1, 3))
    r["n_findings"] = int(sum(1 for k in ("c_identity", "c_section", "c_high_entropy", "c_entropy_content",
                                          "c_api", "c_structural") if c[k] > 0) + rng.poisson(0.4))
    return r


PROFILES = [  # (name, share, label)
    ("benign_app", 0.46, 0), ("benign_packed", 0.10, 0),
    ("mal_packed", 0.16, 1), ("mal_injector", 0.12, 1),
    ("mal_masquerade", 0.08, 1), ("mal_lowsignal", 0.08, 1),
]


def generate_dataset(n=N_SAMPLES, seed=SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for name, share, label in PROFILES:
        for _ in range(int(round(n * share))):
            r = _row(rng, name)
            r["profile"] = name
            r["label"] = label
            rows.append(r)
    df = pd.DataFrame(rows)
    noise = rng.random(len(df)) < 0.02  # 2% label noise keeps the task realistic-ish
    df.loc[noise, "label"] = 1 - df.loc[noise, "label"]
    df["source"] = "SYNTHETIC_DEMO"
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    for col in ALL_FEATURES:
        if df[col].dtype.kind == "f":
            df[col] = df[col].round(4)
    return df[["source", "profile"] + ALL_FEATURES + ["label"]]


# --------------------------------------------------------------------------
# Training + evaluation
# --------------------------------------------------------------------------

def _rf():
    return RandomForestClassifier(n_estimators=200, max_depth=8, min_samples_leaf=8,
                                  max_features="sqrt", random_state=SEED, n_jobs=1)


def _calibrate(rf, X, y, method):
    if FrozenEstimator is not None:
        cal = CalibratedClassifierCV(FrozenEstimator(rf), method=method)
    else:  # pragma: no cover - older scikit-learn
        cal = CalibratedClassifierCV(rf, method=method, cv="prefit")
    return cal.fit(X, y)


def _ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(ece)


def _reliability(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        if m.sum() >= 3:
            out.append({"bin": b, "mean_pred": round(float(p[m].mean()), 4),
                        "frac_pos": round(float(y[m].mean()), 4), "count": int(m.sum())})
    return out


def calibration_map(cal, n=41):
    """The learned raw-score -> probability function (averaged over calibrators,
    exactly as CalibratedClassifierCV.predict_proba does for a binary task)."""
    grid = np.linspace(0, 1, n)
    vals = np.mean([cc.calibrators[0].predict(grid) for cc in cal.calibrated_classifiers_], axis=0)
    return [{"raw": round(float(g), 4), "cal": round(float(v), 4)} for g, v in zip(grid, vals)]


def _cls_metrics(y, p):
    pred = (p >= 0.5).astype(int)
    return {
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, p), 4),
    }


def train(df: pd.DataFrame = None, save_path: str = None, dataset_path: str = None) -> dict:
    if df is None:
        df = generate_dataset()
    if dataset_path:
        os.makedirs(os.path.dirname(dataset_path), exist_ok=True)
        df.to_csv(dataset_path, index=False)

    y = df["label"].to_numpy()
    idx = np.arange(len(df))
    tr, rest = train_test_split(idx, test_size=0.30, stratify=y, random_state=SEED)
    va, te = train_test_split(rest, test_size=0.50, stratify=y[rest], random_state=SEED)

    X_all = df[ALL_FEATURES]
    X_base = df[BASELINE_FEATURES]

    rf_base = _rf().fit(X_base.iloc[tr], y[tr])
    rf_full = _rf().fit(X_all.iloc[tr], y[tr])
    cal_sig = _calibrate(rf_full, X_all.iloc[va], y[va], "sigmoid")
    cal_iso = _calibrate(rf_full, X_all.iloc[va], y[va], "isotonic")

    p_base = rf_base.predict_proba(X_base.iloc[te])[:, 1]
    p_raw = rf_full.predict_proba(X_all.iloc[te])[:, 1]
    p_sig = cal_sig.predict_proba(X_all.iloc[te])[:, 1]
    p_iso = cal_iso.predict_proba(X_all.iloc[te])[:, 1]
    yt = y[te]

    fpr, tpr, _ = roc_curve(yt, p_sig)
    keep = np.unique(np.linspace(0, len(fpr) - 1, min(60, len(fpr))).astype(int))
    tn, fp, fn, tp = confusion_matrix(yt, (p_sig >= 0.5).astype(int)).ravel()

    importances = sorted(zip(ALL_FEATURES, rf_full.feature_importances_), key=lambda t: -t[1])

    metrics = {
        "dataset": {
            "source": "SYNTHETIC_DEMO",
            "rows": int(len(df)), "benign": int((y == 0).sum()), "malicious": int((y == 1).sum()),
            "profiles": df["profile"].value_counts().to_dict(),
            "split": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
            "label_noise": "2%",
        },
        "experiment_1_baseline": _cls_metrics(yt, p_base),
        "experiment_2_contradiction": _cls_metrics(yt, p_raw),
        "experiment_3_calibration": {
            "raw": {"brier": round(brier_score_loss(yt, p_raw), 4), "ece": round(_ece(yt, p_raw), 4)},
            "sigmoid": {"brier": round(brier_score_loss(yt, p_sig), 4), "ece": round(_ece(yt, p_sig), 4)},
            "isotonic": {"brier": round(brier_score_loss(yt, p_iso), 4), "ece": round(_ece(yt, p_iso), 4)},
        },
        "reliability": {"raw": _reliability(yt, p_raw), "calibrated": _reliability(yt, p_sig)},
        "calibration_map": {"sigmoid": calibration_map(cal_sig), "isotonic": calibration_map(cal_iso)},
        "roc": {"fpr": [round(float(fpr[i]), 4) for i in keep], "tpr": [round(float(tpr[i]), 4) for i in keep]},
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "feature_importance": [{"feature": f, "label": FEATURE_LABELS[f], "importance": round(float(v), 4),
                                "group": "contradiction" if f in CONTRADICTION_FEATURES else "baseline"}
                               for f, v in importances],
    }

    bundle = {
        "rf": rf_full, "calibrated": cal_sig, "calibrated_isotonic": cal_iso,
        "features": ALL_FEATURES, "benign_median": df[df.label == 0][ALL_FEATURES].median().to_dict(),
        "metrics": metrics, "method": "sigmoid (Platt scaling)",
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "params": {"n_estimators": 200, "max_depth": 8, "min_samples_leaf": 8, "max_features": "sqrt",
                   "random_state": SEED},
        "demo": True,
    }
    if save_path:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump(bundle, save_path)
    return bundle


# --------------------------------------------------------------------------
# Loading + prediction
# --------------------------------------------------------------------------

_BUNDLE = None


def load_model(model_path: str, dataset_path: str) -> dict:
    """Load the persisted model, (re)training deterministically if it is missing or stale."""
    global _BUNDLE
    if _BUNDLE is not None:
        return _BUNDLE
    bundle = None
    if os.path.exists(model_path):
        try:
            bundle = joblib.load(model_path)
            if bundle.get("sklearn_version") != sklearn.__version__ or bundle.get("features") != ALL_FEATURES:
                bundle = None
        except Exception:
            bundle = None
    if bundle is None:
        bundle = train(save_path=model_path, dataset_path=dataset_path)
    _BUNDLE = bundle
    return bundle


def predict(bundle: dict, vector: dict) -> dict:
    X = pd.DataFrame([vector])[bundle["features"]]
    raw = float(bundle["rf"].predict_proba(X)[0, 1])
    cal = float(bundle["calibrated"].predict_proba(X)[0, 1])
    iso = float(bundle["calibrated_isotonic"].predict_proba(X)[0, 1])

    # Local sensitivity: how much does the raw forest score drop when a single
    # feature is reset to the median benign value? Measured on the raw score
    # because the calibrated probability saturates near 0 and 1.
    med = bundle["benign_median"]
    probes = []
    for feat in bundle["features"]:
        if vector[feat] == med[feat]:
            continue
        Xp = X.copy()
        Xp[feat] = med[feat]
        probes.append((feat, Xp))
    contribs = []
    if probes:
        batch = pd.concat([p for _, p in probes], ignore_index=True)
        pp = bundle["rf"].predict_proba(batch)[:, 1]
        for (feat, _), p in zip(probes, pp):
            contribs.append({"feature": feat, "label": FEATURE_LABELS[feat], "value": vector[feat],
                             "benign_median": round(float(med[feat]), 3), "delta": round(raw - float(p), 4)})
    contribs.sort(key=lambda c: -abs(c["delta"]))

    return {
        "raw_score": round(raw, 4),
        "calibrated_probability": round(cal, 4),
        "isotonic_probability": round(iso, 4),
        "reported_percent": int(round(cal * 100)),
        "method": bundle["method"],
        "verdict": "likely malicious" if cal >= 0.5 else "likely benign",
        "vector": vector,
        "contributions": contribs[:8],
        "model_trained_at": bundle["trained_at"],
        "demo_model": bundle.get("demo", True),
    }


if __name__ == "__main__":  # python -m analyzer.ml_model
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import Config
    b = train(save_path=Config.MODEL_PATH, dataset_path=Config.DATASET_PATH)
    m = b["metrics"]
    print("Trained on SYNTHETIC demo data:", m["dataset"])
    print("Exp1 baseline     :", m["experiment_1_baseline"])
    print("Exp2 +contradiction:", m["experiment_2_contradiction"])
    print("Exp3 calibration  :", m["experiment_3_calibration"])
