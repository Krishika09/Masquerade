"""HTTP routes. All analysis is static - see analyzer/pipeline.py."""
import json
import os

from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, request, url_for)

from analyzer import ml_model, pipeline
from analyzer.contradictions import BUCKETS
from analyzer.samples import (SYNTHETIC_NAME, benign_reference_path,
                              build_synthetic_test_pe)

bp = Blueprint("main", __name__)


def _cfg():
    return current_app.config["MASQ"]


@bp.route("/")
def index():
    return render_template("index.html", recent=pipeline.list_reports(_cfg()),
                           benign_name=os.path.basename(benign_reference_path()))


@bp.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "GET":
        return redirect(url_for("main.index"))
    cfg = _cfg()
    sample = request.form.get("sample")

    if sample == "demo":
        report = pipeline.analyze_demo(cfg)
    elif sample == "synthetic":
        report = pipeline.analyze_bytes(build_synthetic_test_pe(), SYNTHETIC_NAME, cfg, source="synthetic")
    elif sample == "benign":
        path = benign_reference_path()
        with open(path, "rb") as fh:  # read-only; the file is parsed, never launched
            data = fh.read()
        report = pipeline.analyze_bytes(data, os.path.basename(path), cfg, source="benign-reference")
    else:
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            flash("Choose a PE file to upload, or use one of the demo samples below.", "error")
            return redirect(url_for("main.index"))
        data = upload.read()
        if not data:
            flash(f"'{upload.filename}' is empty (0 bytes).", "error")
            return redirect(url_for("main.index"))
        report = pipeline.analyze_bytes(data, upload.filename, cfg, source="upload")
        if cfg.KEEP_UPLOADS:
            # neutral suffix: the stored copy can never be double-click executed
            with open(os.path.join(cfg.UPLOAD_DIR, f"{report['id']}.sample"), "wb") as fh:
                fh.write(data)
    return redirect(url_for("main.report", report_id=report["id"]))


@bp.route("/demo")
def demo():
    report = pipeline.analyze_demo(_cfg())
    return redirect(url_for("main.report", report_id=report["id"]))


@bp.route("/report/<report_id>")
def report(report_id):
    r = pipeline.load_report(report_id, _cfg())
    if r is None:
        abort(404)
    if not r["valid_pe"]:
        return render_template("invalid.html", r=r)
    bundle = ml_model.load_model(_cfg().MODEL_PATH, _cfg().DATASET_PATH)
    return render_template("report.html", r=r, f=r["features"], buckets=BUCKETS,
                           model_metrics=bundle["metrics"])


@bp.route("/features/<report_id>")
def features(report_id):
    r = pipeline.load_report(report_id, _cfg())
    if r is None:
        abort(404)
    payload = r.get("features") or {"valid_pe": False, "file": r["file"], "error": r.get("error")}
    pretty = json.dumps(payload, indent=2, default=str)
    return render_template("features.html", r=r, pretty=pretty, payload=payload)


@bp.route("/features/<report_id>.json")
def features_json(report_id):
    r = pipeline.load_report(report_id, _cfg())
    if r is None:
        abort(404)
    payload = r.get("features") or {"valid_pe": False, "file": r["file"], "error": r.get("error")}
    return Response(json.dumps(payload, indent=2, default=str), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=masquerade-features-{report_id}.json"})


@bp.route("/report/<report_id>.json")
def report_json(report_id):
    r = pipeline.load_report(report_id, _cfg())
    if r is None:
        abort(404)
    return Response(json.dumps(r, indent=2, default=str), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=masquerade-report-{report_id}.json"})


@bp.route("/model")
def model():
    cfg = _cfg()
    bundle = ml_model.load_model(cfg.MODEL_PATH, cfg.DATASET_PATH)
    raw = 0.91  # the PPT's illustrative raw score, mapped through the real calibrator
    cal = float(sum(cc.calibrators[0].predict([raw])[0] for cc in bundle["calibrated"].calibrated_classifiers_)
                / len(bundle["calibrated"].calibrated_classifiers_))
    return render_template("model.html", m=bundle["metrics"], b=bundle, example={"raw": raw, "cal": cal},
                           baseline=ml_model.BASELINE_FEATURES,
                           contradiction=ml_model.CONTRADICTION_FEATURES,
                           labels=ml_model.FEATURE_LABELS)


@bp.route("/about")
def about():
    return render_template("about.html", buckets=BUCKETS)
