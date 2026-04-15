"""
app.py — Flask Backend & API
Starts the sniffer + detector on launch, then serves the dashboard.

Endpoints:
  GET /                 → dashboard HTML
  GET /api/traffic      → last N classified windows (live stats)
  GET /api/alerts       → anomaly-only entries
  GET /api/status       → calibration state + model info
"""

from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from flask_login import LoginManager, login_required, current_user
from core import sniffer, detector
import core.logger as logger
from core.models import init_db, db, User
from core.auth import auth_bp
import random
import time

app = Flask(__name__)
init_db(app)

# Persistent Simulation Store
SIMULATION_CACHE = {
    "flows": [],
    "status": {},
    "stats": {},
    "last_update": 0
}

# Authentication Setup
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

app.register_blueprint(auth_bp)

# ── Startup ───────────────────────────────────────────────────────────────────
@app.before_request
def _startup():
    # Run only once by checking if threads already launched
    pass   # threads are started below in __main__ guard


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/dashboard")
def dashboard():
    # If ?real=1 is passed, force clear demo mode
    if request.args.get('real') == '1':
        session['demo_mode'] = False
        logger.log_system("Switching to REAL monitoring mode.")

    # Allow entry if demo mode is active OR user is logged in
    is_demo = session.get('demo_mode', False)
    if not is_demo and not current_user.is_authenticated:
        return redirect(url_for('landing'))
    return render_template("dashboard.html", is_demo=is_demo)

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/anomaly/<path:flow_id>")
@login_required
def anomaly_detail(flow_id):
    return render_template("anomaly_detail.html", flow_key=flow_id)

@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Explicitly stops the demo simulation and resets session."""
    session['demo_mode'] = False
    logger.log_api("DEMO MODE DEACTIVATED via API.")
    return jsonify({"status": "stopped"})

@app.route("/api/start", methods=["POST"])
def api_start():
    # Handle Demo Mode activation
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "real")
    
    if mode == "demo":
        session['demo_mode'] = True
        logger.log_api("DEMO MODE ACTIVATED — Simulating traffic patterns.")
        return jsonify({"status": "demo_started"})
        
    session['demo_mode'] = False
    
    # Configure detector defaults or based on UI select
    duration = data.get("duration", 30)
    sensitivity = data.get("sensitivity", 0.05)
    detector.set_config(calib_sec=duration, contam=sensitivity)
    
    interface = data.get("interface", None)
    if interface == "" or interface == "auto":
        interface = None
        
    sniffer.start(interface=interface)
    detector.start()
    
    logger.log_api(f"API instructed backend to begin monitoring. IFace: {interface}, Dur: {duration}s")
    return jsonify({"status": "started"})

@app.route("/api/simulation")
def api_simulation():
    """Generates and caches mock SOC metrics."""
    global SIMULATION_CACHE
    now = time.time()
    
    # Regenerate only if cache is empty or stale (> 30s)
    # This keeps investigations stable for the user
    if not SIMULATION_CACHE["flows"] or (now - SIMULATION_CACHE["last_update"] > 30):
        mock_flows = []
        ips = ["192.168.1.10", "10.0.0.5", "172.16.0.2", "8.8.8.8", "1.1.1.1"]
        for i in range(15):
            src = random.choice(ips)
            dst = random.choice([x for x in ips if x != src])
            is_anomaly = random.random() < 0.2
            score = random.uniform(-0.6, -0.2) if is_anomaly else random.uniform(0.1, 0.4)
            
            mock_flows.append({
                "flow_key": f"{src}|{dst}|{random.randint(1024, 65535)}|{random.choice([80, 443, 22])}|TCP",
                "src_ip": src,
                "dst_ip": dst,
                "pkt_count": random.randint(10, 5000),
                "byte_count": random.randint(1000, 5000000),
                "duration_s": random.uniform(1.0, 60.0),
                "avg_iat_ms": random.uniform(0.5, 200.0),
                "score": score,
                "timestamp": now
            })
        
        SIMULATION_CACHE["flows"] = mock_flows
        SIMULATION_CACHE["last_update"] = now
        SIMULATION_CACHE["status"] = {
            "calibrating": False,
            "total_windows": random.randint(500, 2000),
            "total_alerts": len([f for f in mock_flows if f['score'] < 0]),
            "total_classified": random.randint(5000, 20000),
            "mode": "DEMO SIMULATION"
        }
        SIMULATION_CACHE["stats"] = {
            "protocols": {"TCP": 85, "UDP": 10, "ICMP": 5},
            "recent_pkts": random.randint(8000, 25000),
            "recent_bytes": random.randint(2000000, 8000000),
            "top_sources": [{"ip": "192.168.1.10", "bytes": 750000}],
            "top_destinations": [{"ip": "8.8.8.8", "bytes": 1200000}]
        }

    return jsonify(SIMULATION_CACHE)

@app.route("/api/alerts")
def api_alerts():
    if session.get('demo_mode'):
        return jsonify([f for f in SIMULATION_CACHE["flows"] if f['score'] < 0])
    return jsonify(detector.get_alerts())

@app.route("/api/flows")
def api_flows():
    if session.get('demo_mode'):
        return jsonify(SIMULATION_CACHE["flows"])
    return jsonify(detector.get_flows())

@app.route("/api/stats")
def api_stats():
    if session.get('demo_mode'):
        return jsonify(SIMULATION_CACHE["stats"])
    return jsonify(detector.get_stats())

@app.route("/api/status")
def api_status():
    if session.get('demo_mode'):
        return jsonify(SIMULATION_CACHE["status"])
    return jsonify(detector.get_status())


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "POST":
        data = request.json
        detector.set_config(
            calib_sec=data.get("calibration_seconds"),
            contam=data.get("contamination"),
            log_anom=data.get("log_anomalies")
        )
        return jsonify({"status": "updated"})
    return jsonify(detector.get_config())

@app.route("/api/traffic")
def api_traffic():
    if session.get('demo_mode'):
        return jsonify(SIMULATION_CACHE["flows"][:100])
    with detector._results_lock:
        data = list(detector.results_store[-100:])
    return jsonify(data)

@app.route("/api/related_flows/<path:ip>")
def api_related_flows(ip):
    if session.get('demo_mode'):
        matches = [f for f in SIMULATION_CACHE["flows"] if f['src_ip'] == ip or f['dst_ip'] == ip]
        return jsonify(matches[:30])
        
    # Fetch any flows where src or dst matches IP from detector
    with detector._results_lock:
        matches = [r for r in detector.results_store if r.get("src_ip") == ip or r.get("dst_ip") == ip]
        matches = matches[-30:]
        matches.reverse()
    return jsonify(matches)



# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    dev_mode = "--dev" in sys.argv
    logger.init_logger(dev_mode=dev_mode)

    # Start Flask (threaded mode for concurrent API requests)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
