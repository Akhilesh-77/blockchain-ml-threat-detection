"""
CyberNex Backend Configuration.
Environment variables, database paths, and API settings.
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BACKEND_DIR / "cyber_nex.db"

# Database URL: uses SQLite local development by default, or PostgreSQL if configured
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH.as_posix()}")

# Security & CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000").split(",")

# ML Model Paths
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "rf_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# Blockchain Configuration
BLOCKCHAIN_DIFFICULTY = int(os.getenv("BLOCKCHAIN_DIFFICULTY", "2"))
GENESIS_PREV_HASH = "0" * 64

