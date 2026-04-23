"""
app.py — Main Entry Point
Imports and runs the Flask application from the refactored backend.
"""

from backend.api.routes import create_app, socketio
import backend.analysis.logger as logger
import sys

if __name__ == "__main__":
    dev_mode = "--dev" in sys.argv
    logger.init_logger(dev_mode=dev_mode)

    app = create_app()

    # Start Flask with SocketIO (threaded mode for concurrent API requests)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
