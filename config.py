"""
Configuration module for Blockchain-Audited ML System for Encrypted Threat Detection.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
MODELS_DIR = BASE_DIR / "models"
DB_DIR = BASE_DIR / "database"
DB_PATH = DB_DIR / "audit_ledger.db"

# Ensure runtime directories exist
SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

# Model Artifact Paths
MODEL_PATH = MODELS_DIR / "rf_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# Feature definitions for Encrypted Network Metadata
# Features are derived from flow metrics without payload decryption
FEATURE_COLUMNS = [
    "flow_duration",             # Total duration of flow in seconds
    "total_fwd_packets",        # Total packets forwarded (client -> server)
    "total_bwd_packets",        # Total packets received (server -> client)
    "total_fwd_bytes",          # Total bytes in forward direction
    "total_bwd_bytes",          # Total bytes in backward direction
    "fwd_packet_length_mean",   # Average size of forward packets
    "bwd_packet_length_mean",   # Average size of backward packets
    "flow_bytes_per_sec",       # Flow byte rate (bytes/s)
    "flow_packets_per_sec",     # Flow packet rate (packets/s)
    "flow_iat_mean",            # Flow inter-arrival time mean (seconds)
    "flow_iat_std",             # Flow inter-arrival time standard deviation
    "fwd_iat_mean",             # Forward IAT mean
    "bwd_iat_mean",             # Backward IAT mean
    "packet_length_mean",       # Overall mean packet size
    "packet_length_std",        # Standard deviation of packet size
    "syn_flag_count",           # TCP SYN count (connection setup behavior)
    "rst_flag_count",           # TCP RST count (abrupt teardown behavior)
    "psh_flag_count",           # TCP PSH count (immediate push / streaming)
    "ack_flag_count",           # TCP ACK count
    "fin_flag_count",           # TCP FIN count
    "down_up_ratio",            # Backward-to-Forward packet ratio
]

# Classification Labels
CLASS_NAMES = ["Normal", "Suspicious", "Malicious"]
CLASS_MAPPING = {
    0: "Normal",
    1: "Suspicious",
    2: "Malicious"
}
LABEL_TO_ID = {v: k for k, v in CLASS_MAPPING.items()}

# Class Descriptions
CLASS_DESCRIPTIONS = {
    "Normal": "Legitimate encrypted TLS traffic (e.g. HTTPS browsing, authorized cloud APIs, standard CDN access).",
    "Suspicious": "Anomalous encrypted session behavior (e.g. DoH/Tor tunneling, beaconing patterns, unusual IAT variance).",
    "Malicious": "High-confidence malicious activity (e.g. Encrypted C2 exfiltration, volumetric encrypted scanning, TLS tunnel brute force)."
}

# Blockchain Specifications
GENESIS_PREV_HASH = "0" * 64
HASH_ALGORITHM = "SHA-256"
BLOCKCHAIN_DIFFICULTY = 2  # Prefix zeroes required for proof-of-work (lightweight demonstration)

# UI SOC Color Palette
PALETTE = {
    "bg_dark": "#0B0F19",
    "card_bg": "#111827",
    "border": "#1F2937",
    "normal": "#10B981",       # Emerald
    "suspicious": "#F59E0B",   # Amber
    "malicious": "#EF4444",    # Red
    "cyan": "#06B6D4",         # Cyan / Accent
    "purple": "#8B5CF6",       # Purple
    "text": "#E5E7EB",         # Light grey text
    "text_muted": "#9CA3AF"    # Muted text
}
