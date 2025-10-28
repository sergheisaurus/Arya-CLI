#!/usr/bin/env python3
"""
App launcher for ARYA Viewer.

Refactored into a proper Flask package under `arya_web/` with:
- Config in `arya_web/config.py`
- Views in `arya_web/views/main.py`
- Services in `arya_web/services/`
- Templates under `arya_web/templates/`
"""

from arya_web import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
