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

from backend.capture import sniffer
import backend.analysis.logger as logger
from backend.detection import classify, rules
from backend.analysis import explain, baseline
from backend.models.models import db, Alert, Anomaly, BaselineStat

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
_on_alert_callback = None


def _generate_actions(attack_type, anomaly_data):
    """
    Generate actionable recommendations based on attack type.
    
    Returns: list of action strings
    """
    actions = []
    src_ip = anomaly_data.get('src_ip', 'unknown')
    
    if attack_type == "DDoS":
        actions = [
            f"Block IP {src_ip} at firewall",
            "Rate limit incoming traffic on affected ports",
            f"Investigate device {src_ip} for compromise"
        ]
    elif attack_type == "Port Scan":
        actions = [
            f"Block IP {src_ip} at firewall",
            "Monitor for further scanning activity",
            f"Check logs for successful connections from {src_ip}"
        ]
    elif attack_type == "Spoofing":
        actions = [
            f"Inspect ARP table for IP {src_ip}",
            "Enable ARP inspection on network switches",
            f"Verify device identity for {src_ip}"
        ]
    elif attack_type == "Data Exfiltration":
        actions = [
            f"Block outbound traffic from {src_ip}",
            "Enable DLP (Data Loss Prevention) monitoring",
            f"Investigate data accessed by {src_ip}"
        ]
    else:
        actions = [
            f"Investigate IP {src_ip} for suspicious activity",
            "Review recent network logs",
            "Consider temporary blocking if threat persists"
        ]
    
    return actions

def _save_alert_to_db(alert_data):
    """Save alert to database."""
    try:
        alert = Alert(
            attack_type=alert_data.get('attack_type'),
            confidence=alert_data.get('confidence'),
            severity=_determine_severity(alert_data),
            src_ip=alert_data.get('src_ip'),
            description=f"Anomaly detected: {alert_data.get('attack_type', 'Unknown')}",
            explanation=json.dumps(alert_data.get('explanation', {})),
            actions=json.dumps(alert_data.get('actions', []))
        )
        db.session.add(alert)
        db.session.commit()
        if _on_alert_callback:
            _on_alert_callback(alert_data)
    except Exception as e:
        logger.log_system(f"Failed to save alert to DB: {e}")

def _save_anomaly_to_db(anomaly_data):
    """Save anomaly classification to database."""
    try:
        anomaly = Anomaly(
            flow_key=anomaly_data.get('flow_key', ''),
            score=anomaly_data.get('score', 0),
            features=json.dumps(anomaly_data),
            attack_type=anomaly_data.get('attack_type'),
            confidence=anomaly_data.get('confidence', 0)
        )
        db.session.add(anomaly)
        db.session.commit()
    except Exception as e:
        logger.log_system(f"Failed to save anomaly to DB: {e}")

def _determine_severity(alert_data):
    """Determine severity based on confidence and attack type."""
    confidence = alert_data.get('confidence', 0)
    attack_type = alert_data.get('attack_type', '')
    
    if attack_type in ['DDoS', 'Data Exfiltration'] or confidence > 0.8:
        return 'critical'
    elif attack_type == 'Port Scan' or confidence > 0.6:
        return 'high'
    elif confidence > 0.4:
        return 'medium'
    else:
        return 'low'
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

            # Update baseline with normal traffic
            if pred == 1:  # Normal
                baseline.baseline_learner.update({
                    'packet_rate': row.get('pkt_count', 0) / row.get('duration_s', 1),
                    'byte_rate': row.get('byte_count', 0) / row.get('duration_s', 1),
                    'unique_ips': 1,  # Simplified
                    'unique_ports': 1
                })

            with _results_lock:
                results_store.append(classified)
                if len(results_store) > 500:
                    del results_store[:100]

            if pred == -1:
                # Classify attack type
                attack_type, confidence = classify.attack_classifier.predict(vec)
                classified["attack_type"] = attack_type
                classified["confidence"] = round(confidence, 3)
                
                # Generate explanation
                explanation = explain.explainer.explain_anomaly(classified)
                classified["explanation"] = explanation
                
                # Generate actionable recommendations
                actions = _generate_actions(attack_type, classified)
                classified["actions"] = actions
                
                alerts_store.append(classified)
                if len(alerts_store) > 200:
                    del alerts_store[:50]
                    
                    # Save to database
                    _save_alert_to_db(classified)
                
                # Save all classifications to DB (optional, for analytics)
                _save_anomaly_to_db(classified)
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

def start(on_alert_callback=None):
    """Start the detector worker as a background daemon thread."""
    global _is_running, _on_alert_callback
    if _is_running:
        return
    _on_alert_callback = on_alert_callback
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
