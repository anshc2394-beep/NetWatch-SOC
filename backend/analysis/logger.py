"""
logger.py — Centralized Rich Logger for NetWatch AI
Provides structured, categorized, and colored terminal output.
"""

import logging
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
from rich.theme import Theme
from rich.live import Live

# Custom visual theme
_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "red bold",
    "success": "green"
})

console = Console(theme=_theme)
_dev_mode = False

# Silence default Werkzeug HTTP server logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def init_logger(dev_mode=False):
    global _dev_mode
    _dev_mode = dev_mode
    console.print(Panel.fit(
        "[bold cyan]NetWatch AI[/bold cyan] — Advanced Intrusion Detection Console\n"
        "[italic]System initialized. Waiting for dashboard trigger...[/italic]",
        border_style="cyan"
    ))

def _print_prefix(prefix: str, color: str, msg: str):
    time_str = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{time_str}[/dim] [[bold {color}]{prefix:^7}[/bold {color}]] {msg}")

def log_system(msg: str):
    _print_prefix("SYSTEM", "white", msg)

def log_capture(msg: str):
    # Depending on mode, we might hide routine capture logs.
    if _dev_mode:
        _print_prefix("CAPTURE", "blue", msg)

def log_model(msg: str):
    _print_prefix("MODEL", "magenta", msg)

def log_api(msg: str):
    if _dev_mode:
        _print_prefix("API", "green", msg)

def log_alert(flow_info: dict, score: float):
    """Render a detailed multi-line anomaly alert panel."""
    if score <= -0.1:
        sev_color = "red"
        sev_label = "HIGH"
    elif score < 0:
        sev_color = "yellow"
        sev_label = "MEDIUM"
    else:
        sev_color = "green"
        sev_label = "LOW"
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold " + sev_color)
    table.add_column("Value", style="white")

    # Add flow fields
    table.add_row("Flow Object", flow_info.get("flow_key", "Unknown"))
    table.add_row("Packets", str(flow_info.get("pkt_count", 0)))
    table.add_row("Bytes", str(flow_info.get("byte_count", 0)))
    table.add_row("Avg IAT (ms)", str(round(flow_info.get("avg_iat_ms", 0), 2)))
    table.add_row("Anomaly Score", f"[{sev_color}]{round(score, 4)}[/{sev_color}]")

    panel = Panel(
        table,
        title=f"[bold {sev_color}]⚠️ ANOMALY DETECTED ({sev_label} SEVERITY)[/bold {sev_color}]",
        border_style=sev_color,
        expand=False
    )
    console.print(panel)

# A simple Live status bar wrapper could be implemented, but given threaded nature, 
# frequent individual console prints over a Live render works much more robustly 
# alongside background logs. If requested, a periodic status summary is cleaner.
def print_status_summary(calibrating, sample_count, window_count, total_alerts, last_retrain_time):
    """Print a clean compact status matrix instead of a persistent Live display (which conflicts with async logs)."""
    state_str = "[yellow]Calibrating...[/yellow]" if calibrating else "[green]Monitoring Active[/green]"
    
    t = Table(title="[bold]Backend Status Summary[/bold]", style="cyan")
    t.add_column("State", justify="center")
    t.add_column("Baseline Samples", justify="right")
    t.add_column("Total Windows", justify="right")
    t.add_column("Total Alerts", justify="right", style="red")
    
    t.add_row(state_str, str(sample_count), str(window_count), str(total_alerts))
    console.print(t)
