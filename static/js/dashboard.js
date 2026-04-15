/**
 * dashboard.js — SOC SaaS Engine
 */

let pollInterval = null;
const POLL_MS = 3000;
const MAX_POINTS = 30;

// charts
let trafficChart, scoreChart;

// ── Initialization ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    
    if (IS_DEMO) {
        startSimulation();
    } else {
        // Initial state check
        checkSystemStatus();
    }
});

function initCharts() {
    const commonOpts = {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { 
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { display: false } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#475569', font: {size: 10} } }
        }
    };

    trafficChart = new Chart(document.getElementById('chart-traffic'), {
        type: 'line',
        data: { labels: [], datasets: [{ 
            data: [], borderColor: '#4F9CF9', backgroundColor: 'rgba(79,156,249,0.1)', fill: true, tension: 0.4 
        }] },
        options: commonOpts
    });

    scoreChart = new Chart(document.getElementById('chart-score'), {
        type: 'line',
        data: { labels: [], datasets: [{ 
            data: [], borderColor: '#2DD4BF', tension: 0.4,
            segment: { borderColor: ctx => ctx.p1.parsed.y < 0 ? '#EF4444' : '#2DD4BF' }
        }] },
        options: { ...commonOpts, scales: { ...commonOpts.scales, y: { suggestedMin: -0.2, suggestedMax: 0.2 } } }
    });
}

// ── State Monitoring ──────────────────────────────────────────────────────────

async function checkSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const status = await res.json();
        if (status.calibrating || status.total_classified > 0) {
            startPolling();
        } else {
            // Show config modal if first time
            openConfig();
        }
    } catch(e) {}
}

function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollData, POLL_MS);
    pollData();
}

async function pollData() {
    const endpoint = IS_DEMO ? '/api/simulation' : '/api/status'; 
    // In real mode we need multiple fetches, in demo simulation returns everything in one go
    
    try {
        if (IS_DEMO) {
            const data = await (await fetch('/api/simulation')).json();
            updateUI(data.status, data.flows, data.stats);
        } else {
            const status = await (await fetch('/api/status')).json();
            const flows = await (await fetch('/api/flows')).json();
            const stats = await (await fetch('/api/stats')).json();
            updateUI(status, flows, stats);
        }
    } catch(e) { console.error("Poll error", e); }
}

function updateUI(status, flows, stats) {
    // Update stats
    document.getElementById('val-rhythm').innerText = stats.recent_pkts + " pkts/s";
    document.getElementById('val-density').innerText = status.total_alerts + " alerts found";
    document.getElementById('val-risk').innerText = Math.min(status.total_alerts * 5, 100) + " / 100";
    
    // AI Insights (Mocked for now, but changes based on alerts)
    const insight = document.getElementById('val-insight');
    if (status.total_alerts > 0) {
        insight.innerText = "Significant deviation in encrypted flow entropy detected. Recommendation: Isolate host 192.168.1.10.";
        insight.style.color = 'var(--accent-amber)';
    } else {
        insight.innerText = "Baseline traffic nominal. No suspicious clustering patterns observed.";
        insight.style.color = 'var(--text-muted)';
    }

    // Entropy & Variance
    document.getElementById('val-entropy').innerText = (0.8 + Math.random() * 0.1).toFixed(3);
    document.getElementById('val-variance').innerText = (12 + Math.random() * 5).toFixed(1);

    // Update charts
    const time = new Date().toLocaleTimeString();
    pushChart(trafficChart, time, stats.recent_pkts);
    const avgScore = flows.length > 0 ? flows[0].score : 0;
    pushChart(scoreChart, time, avgScore);

    // Update Table
    const tbody = document.getElementById('flow-tbody');
    tbody.innerHTML = flows.map(f => `
        <tr onclick="window.location.href='/anomaly/${encodeURIComponent(f.flow_key)}'" style="cursor:pointer">
            <td class="font-mono" style="font-size:0.75rem">${shorten(f.flow_key)}</td>
            <td>${f.pkt_count}</td>
            <td style="color:${f.score < 0 ? 'var(--accent-red)' : 'var(--accent-cyan)'}">${f.score.toFixed(3)}</td>
            <td><span class="badge badge--${f.score < 0 ? 'anomaly' : 'normal'}">${f.score < 0 ? 'SUSPECT' : 'CLEAN'}</span></td>
        </tr>
    `).join("") || "<tr><td colspan='4'>Monitoring active...</td></tr>";

    // Update Alert List
    const alerts = flows.filter(f => f.score < 0);
    const list = document.getElementById('alert-list');
    if (alerts.length > 0) {
        list.innerHTML = alerts.map(a => `<li class="alert-item alert-item--high">
            <div class="alert-key">${shorten(a.flow_key)}</div>
            <div class="alert-meta">Score: ${a.score.toFixed(4)}</div>
        </li>`).join("");
    } else if (list.innerHTML.includes('skeleton')) {
        list.innerHTML = '<li class="alert-empty">No threats detected</li>';
    }

    // Update Topbar Status
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-label');
    const winChip = document.getElementById('chip-windows');
    const alertChip = document.getElementById('chip-alerts');

    if (dot && label) {
        if (IS_DEMO) {
            dot.className = 'status-dot live';
            label.innerText = 'STREAMING (SIMULATED)';
        } else if (status.calibrating) {
            dot.className = 'status-dot calib';
            label.innerText = 'CALIBRATING ENGINE...';
        } else {
            dot.className = 'status-dot live';
            label.innerText = 'MONITORING ACTIVE';
        }
    }
    if (winChip) winChip.innerText = `${status.total_windows} windows`;
    if (alertChip) alertChip.innerText = `${status.total_alerts} threats`;
}

// ── Modal & Actions ───────────────────────────────────────────────────────────

function openConfig() { document.getElementById('config-modal').style.display = 'flex'; }
function closeConfig() { document.getElementById('config-modal').style.display = 'none'; }

async function startMonitoring() {
    const payload = {
        interface: document.getElementById('cfg-iface').value,
        duration: parseInt(document.getElementById('cfg-dur').value),
        sensitivity: parseFloat(document.getElementById('cfg-sens').value)
    };
    
    closeConfig();
    try {
        await fetch('/api/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        startPolling();
    } catch(e) { alert("Engine startup failed."); }
}

function startSimulation() {
    IS_DEMO = true;
    const startBtn = document.getElementById('btn-start');
    if (startBtn) {
        startBtn.innerText = "DEMO SIMULATION ACTIVE";
        startBtn.style.background = "var(--border)";
        startBtn.disabled = true;
    }
    startPolling();
}

async function stopSimulation() {
    try {
        await fetch('/api/stop', { method: 'POST' });
    } catch(e) {}

    if (pollInterval) clearInterval(pollInterval);
    IS_DEMO = false;
    
    // Reset buttons and badges
    const btn = document.getElementById('btn-start');
    if (btn) {
        btn.innerText = "Start Real-time Monitoring";
        btn.style.background = "var(--accent-primary)";
        btn.disabled = false;
        btn.style.display = 'inline-block'; // Restore if it was hidden
    }
    
    // UI Cleanup
    const badge = document.querySelector('.demo-badge');
    if (badge) badge.remove();
    
    // Remove the stop button itself
    const stopBtn = document.querySelector('button[onclick="stopSimulation()"]');
    if (stopBtn) stopBtn.remove();

    // Clear Charts
    if (trafficChart) {
        trafficChart.data.labels = [];
        trafficChart.data.datasets[0].data = [];
        trafficChart.update();
    }
    if (scoreChart) {
        scoreChart.data.labels = [];
        scoreChart.data.datasets[0].data = [];
        scoreChart.update();
    }

    // Refresh Topbar Status to reflect standby
    const label = document.getElementById('status-label');
    const dot = document.getElementById('status-dot');
    if (label) label.innerText = "ENGINE STANDBY";
    if (dot) dot.className = "status-dot";

    // Open Config for Real Capture
    openConfig();
}

// ── Utils ────────────────────────────────────────────────────────────────────

function pushChart(chart, label, val) {
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(val);
    if(chart.data.labels.length > MAX_POINTS) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.update('none');
}

function shorten(k) { return k.length > 25 ? '...' + k.slice(-22) : k; }
