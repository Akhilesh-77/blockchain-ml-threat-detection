"""
Seed script to populate initial traffic sessions and blockchain ledger blocks
with genuine data from the trained ML model.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blockchain.ledger import get_ledger
from config import SAMPLE_DATA_DIR
from database.db import get_db
from ml.predict import get_predictor
from network.feature_extraction import anonymize_ip


def seed_initial_soc_data(count: int = 25) -> None:
    """Populate database and blockchain ledger with real ML classified sessions."""
    db = get_db()
    ledger = get_ledger()
    predictor = get_predictor()

    if db.get_block_count() > 1 and len(db.get_all_sessions()) >= count:
        print("Database already populated with initial SOC sessions.")
        return

    csv_path = SAMPLE_DATA_DIR / "encrypted_traffic_sample.csv"
    if not csv_path.exists():
        from ml.train import train_model
        train_model()

    df = pd.read_csv(csv_path).head(count)
    preds = predictor.predict_batch(df)

    base_time = datetime.now(timezone.utc) - timedelta(minutes=count * 3)

    for i, (_, row) in enumerate(preds.iterrows()):
        session_time = (base_time + timedelta(minutes=i * 3)).isoformat()
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"

        src_ip = f"192.168.1.{100 + (i % 50)}"
        dst_ip = f"104.26.{10 + (i % 20)}.{1 + (i % 250)}"
        port = 443 if row["prediction"] != "Suspicious" else 8443

        features = {col: float(row[col]) for col in df.columns if col not in ["label", "prediction", "confidence", "prediction_id"]}

        # 1. Store session
        db.insert_session({
            "session_id": session_id,
            "timestamp": session_time,
            "src_ip_hash": anonymize_ip(src_ip),
            "dst_ip_hash": anonymize_ip(dst_ip),
            "dst_port": port,
            "protocol": "TCP/TLS 1.3",
            "features": features,
            "prediction": row["prediction"],
            "confidence": float(row["confidence"]),
            "audited": 1,
            "block_index": None
        })

        # 2. Mine an audit block in the blockchain ledger
        block = ledger.create_detection_record(
            prediction=row["prediction"],
            confidence=float(row["confidence"]),
            metadata_summary={
                "flow_duration": features.get("flow_duration", 1.0),
                "total_fwd_packets": features.get("total_fwd_packets", 10),
                "total_bwd_packets": features.get("total_bwd_packets", 10),
                "total_fwd_bytes": features.get("total_fwd_bytes", 1000),
                "total_bwd_bytes": features.get("total_bwd_bytes", 1000),
                "dst_port": port,
                "protocol": "TCP/TLS 1.3",
                "flow_bytes_per_sec": features.get("flow_bytes_per_sec", 1000.0),
                "flow_packets_per_sec": features.get("flow_packets_per_sec", 10.0),
            },
            event_id=f"EVT-{session_id}"
        )

        db.mark_session_audited(session_id, block.index_num)

    print(f"Successfully seeded {count} audited SOC sessions into SQLite and Blockchain ledger!")


if __name__ == "__main__":
    seed_initial_soc_data()
