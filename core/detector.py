"""
detector.py — Adaptive Anomaly Detection with Sliding-Window Retraining
Uses Isolation Forest; retrains every RETRAIN_INTERVAL_S on the last
SLIDING_WINDOW_SIZE feature vectors for dynamic network conditions.
"""

import json
import os
import time
import threading
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core import sniffer
import core.logger as logger

# ── Configuration Variables ───────────────────────────────────────────────────
CALIBRATION_SECONDS   = 30      # gather baseline before first fit
RETRAIN_INTERVAL_S    = 20      # retrain model every 20 s
SLIDING_WINDOW_SIZE   = 100     # features kept for retraining
CONTAMINATION         = 0.05    # expected anomaly fraction
ANOMALY_LOG_PATH      = os.path.join("data", "anomalies.json")
LOG_ANOMALIES         = True

# Feature columns used by the model (must match sniffer.py output)
FEATURE_COLS = ["pkt_count", "byte_count", "duration_s",
                "avg_pkt_size", "avg_iat_ms", "max_iat_ms"]

# ── Shared results store ───────────────────────────────────────────────────────
_results_lock  = threading.Lock()
results_store: list = []          # list of dicts  (all classified windows)
alerts_store:  list = []          # anomaly-only windows

_model: IsolationForest | None = None
_scaler: StandardScaler         = StandardScaler()
_calibrating: bool              = True
_calibration_start: float       = 0.0
_last_retrain: float            = 0.0


def _extract_features(row: dict) -> list | None:
    """Convert a feature-window dict → numeric vector."""
    try:
        return [float(row[c]) for c in FEATURE_COLS]
    except (KeyError, ValueError, TypeError):
        return None


def _fit_model(X: np.ndarray):
    """Fit (or re-fit) the IsolationForest on X."""
    global _model, _scaler
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)
    _model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=42,
    )
    _model.fit(X_scaled)


def _log_alert(row: dict, score: float):
    """Append the anomaly to the JSON log file."""
    os.makedirs("logs", exist_ok=True)
    entry = {
        "timestamp":    datetime.utcfromtimestamp(row["timestamp"]).isoformat() + "Z",
        "src_ip":       row.get("src_ip", ""),
        "dst_ip":       row.get("dst_ip", ""),
        "src_port":     row.get("src_port", ""),
        "dst_port":     row.get("dst_port", ""),
        "proto":        row.get("proto", ""),
        "flow_key":     row.get("flow_key", ""),
        "pkt_count":    row.get("pkt_count"),
        "byte_count":   row.get("byte_count"),
        "avg_pkt_size": row.get("avg_pkt_size"),
        "duration_s":   row.get("duration_s"),
        "avg_iat_ms":   row.get("avg_iat_ms"),
        "anomaly_score": round(score, 4),
    }
    try:
        # Read existing list, append, write back
        if os.path.isfile(ANOMALY_LOG_PATH):
            with open(ANOMALY_LOG_PATH, "r") as f:
                existing: list = json.load(f)
        else:
            existing = []
        existing.append(entry)
        with open(ANOMALY_LOG_PATH, "w") as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        logger.log_system(f"Detector log write error: {e}")


def _detector_loop():
    """
    Main worker loop:
      1. Wait for sniffer to produce feature windows.
      2. Calibrate for CALIBRATION_SECONDS.
      3. Classify each new window; retrain every RETRAIN_INTERVAL_S.
    """
    global _calibrating, _calibration_start, _last_retrain

    logger.log_model("Starting Initial Calibration Phase...")
    _calibration_start = time.time()
    processed_up_to = 0   # index into sniffer.feature_windows

    while True:
        time.sleep(1)

        with sniffer.feature_windows_lock:
            new_rows = sniffer.feature_windows[processed_up_to:]

        if not new_rows:
            continue

        # ── Calibration phase ─────────────────────────────────────────
        if _calibrating:
            elapsed = time.time() - _calibration_start
            if elapsed >= CALIBRATION_SECONDS:
                # Enough baseline data — do first fit
                with sniffer.feature_windows_lock:
                    all_rows = list(sniffer.feature_windows)

                X_all = [_extract_features(r) for r in all_rows]
                X_all = [v for v in X_all if v is not None]

                if len(X_all) >= 5:
                    _fit_model(np.array(X_all))
                    _calibrating = False
                    _last_retrain = time.time()
                    processed_up_to = len(all_rows)
                    logger.log_model(f"Calibration Complete. Model trained on {len(X_all)} samples.")
                else:
                    logger.log_system("Not enough samples yet — extending calibration...")
            continue   # keep collecting during calibration

        # ── Classification phase ──────────────────────────────────────
        for row in new_rows:
            vec = _extract_features(row)
            if vec is None:
                continue

            X = _scaler.transform([vec])
            pred   = _model.predict(X)[0]          # 1 = normal, -1 = anomaly
            score  = _model.decision_function(X)[0] # higher = more normal

            classified = {**row, "prediction": int(pred), "score": round(float(score), 4)}

            with _results_lock:
                results_store.append(classified)
                if len(results_store) > 500:
                    del results_store[:100]

                if pred == -1:
                    alerts_store.append(classified)
                    if len(alerts_store) > 200:
                        del alerts_store[:50]

            if pred == -1:
                # Log to UI
                _log_alert(row, score)
                # Render Rich multi-line panel
                if LOG_ANOMALIES:
                    logger.log_alert(row, score)

        processed_up_to += len(new_rows)

        # ── Sliding-window retraining ─────────────────────────────────
        if time.time() - _last_retrain >= RETRAIN_INTERVAL_S:
            _last_retrain = time.time()

            # Copy state to pass into worker thread safely
            with sniffer.feature_windows_lock:
                recent = list(sniffer.feature_windows[-SLIDING_WINDOW_SIZE:])

            def _background_retrain(recent_windows):
                X_retrain = [_extract_features(r) for r in recent_windows]
                X_retrain = [v for v in X_retrain if v is not None]

                if len(X_retrain) >= 5:
                    _fit_model(np.array(X_retrain))
                    logger.log_model(f"Model dynamically retrained on {len(X_retrain)} recent windows.")

            retrain_thread = threading.Thread(target=_background_retrain, args=(recent,), daemon=True, name="RetrainWorker")
            retrain_thread.start()


_is_running = False

# ── Public API ────────────────────────────────────────────────────────────────
def set_config(calib_sec=None, contam=None, log_anom=None):
    global CALIBRATION_SECONDS, CONTAMINATION, LOG_ANOMALIES
    if calib_sec is not None:
        CALIBRATION_SECONDS = int(calib_sec)
    if contam is not None:
        CONTAMINATION = float(contam)
    if log_anom is not None:
        LOG_ANOMALIES = bool(log_anom)
    logger.log_system(f"Detector config updated: {CALIBRATION_SECONDS}s, {CONTAMINATION} contam.")

def get_config():
    return {
        "calibration_seconds": CALIBRATION_SECONDS,
        "contamination": CONTAMINATION,
        "log_anomalies": LOG_ANOMALIES
    }

def start():
    """Start the detector worker as a background daemon thread."""
    global _is_running
    if _is_running:
        return
    _is_running = True
    t = threading.Thread(target=_detector_loop, daemon=True, name="DetectorWorker")
    t.start()
    logger.log_system("Detector worker thread started.")


def is_calibrating() -> bool:
    return _calibrating

def get_alerts():
    with _results_lock:
        return list(alerts_store)

def get_flows():
    with _results_lock:
        # Return last 20 newest first for UI
        res = list(results_store[-20:])
        res.reverse()
        return res

def get_status():
    return {
        "calibrating":      _calibrating,
        "queue_size":       sniffer.packet_queue.qsize(),
        "total_windows":    len(sniffer.feature_windows),
        "total_classified": len(results_store),
        "total_alerts":     len(alerts_store),
    }

def get_stats():
    # Simple aggregation for dashboard
    with _results_lock:
        recent = list(results_store[-200:])
    
    from collections import Counter
    proto_counts = Counter()
    src_bytes = Counter()
    dst_bytes = Counter()
    total_pkts = 0
    total_bytes = 0

    for r in recent:
        proto_counts[r.get("proto", "Other")] += 1
        b = r.get("byte_count", 0)
        p = r.get("pkt_count", 0)
        src = r.get("src_ip")
        dst = r.get("dst_ip")
        if src: src_bytes[src] += b
        if dst: dst_bytes[dst] += b
        total_pkts += p
        total_bytes += b

    return {
        "protocols": dict(proto_counts),
        "top_sources": [{"ip": k, "bytes": v} for k, v in src_bytes.most_common(5)],
        "top_destinations": [{"ip": k, "bytes": v} for k, v in dst_bytes.most_common(5)],
        "recent_pkts": total_pkts,
        "recent_bytes": total_bytes
    }
