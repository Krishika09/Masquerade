"""Central configuration for Masquerade."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    APP_NAME = "Masquerade"
    APP_VERSION = "0.8.0"

    SECRET_KEY = os.environ.get("MASQUERADE_SECRET", "masquerade-local-dev-key")

    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
    REPORT_DIR = os.path.join(BASE_DIR, "reports")
    MODEL_DIR = os.path.join(BASE_DIR, "models")
    DATA_DIR = os.path.join(BASE_DIR, "data")

    MODEL_PATH = os.path.join(MODEL_DIR, "masquerade_rf_calibrated.joblib")
    DATASET_PATH = os.path.join(DATA_DIR, "demo_training_features.csv")

    # Uploads are parsed statically only. Files are stored with a neutral
    # ".sample" suffix so they can never be double-clicked into execution.
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    KEEP_UPLOADS = True

    HOST = "127.0.0.1"
    PORT = 5000
