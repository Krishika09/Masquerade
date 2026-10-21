"""Masquerade - Explainable Static Malware Triage (localhost prototype).

    pip install -r requirements.txt
    python app.py            ->  http://127.0.0.1:5000

Uploaded files are parsed statically with pefile. They are never executed,
imported, or passed to a subprocess.
"""
import math
import os

from flask import Flask, render_template

from analyzer import ml_model
from config import Config
from routes.main import bp


def create_app(cfg=Config):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_CONTENT_LENGTH
    app.config["MASQ"] = cfg
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    for d in (cfg.UPLOAD_DIR, cfg.REPORT_DIR, cfg.MODEL_DIR, cfg.DATA_DIR):
        os.makedirs(d, exist_ok=True)

    app.register_blueprint(bp)

    @app.context_processor
    def inject_globals():
        return {"app_name": cfg.APP_NAME, "app_version": cfg.APP_VERSION}

    @app.template_filter("hexn")
    def hexn(v, width=8):
        try:
            return f"0x{int(v):0{width}X}"
        except (TypeError, ValueError):
            return "-"

    @app.template_global("gauge_arc")
    def gauge_arc(v0, v1, cx=130, cy=124, r=100):
        """SVG path for the semicircular risk gauge from score v0 to v1 (0-100)."""
        a0 = math.pi * (1 - max(0, min(100, v0)) / 100)
        a1 = math.pi * (1 - max(0, min(100, v1)) / 100)
        x0, y0 = cx + r * math.cos(a0), cy - r * math.sin(a0)
        x1, y1 = cx + r * math.cos(a1), cy - r * math.sin(a1)
        return f"M{x0:.2f},{y0:.2f} A{r},{r} 0 0 1 {x1:.2f},{y1:.2f}"

    @app.template_filter("num")
    def num(v):
        try:
            return f"{int(v):,}"
        except (TypeError, ValueError):
            return v

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, title="Report not found",
                               message="That report ID does not exist. Reports are stored locally in /reports."), 404

    @app.errorhandler(413)
    def too_large(_e):
        mb = cfg.MAX_CONTENT_LENGTH // (1024 * 1024)
        return render_template("error.html", code=413, title="File too large",
                               message=f"The upload limit for this prototype is {mb} MB."), 413

    # Train (deterministically) or load the demo model once at start-up.
    ml_model.load_model(cfg.MODEL_PATH, cfg.DATASET_PATH)
    return app


app = create_app()

if __name__ == "__main__":
    print(f"\n  Masquerade running at http://{Config.HOST}:{Config.PORT}  (static analysis only)\n")
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
