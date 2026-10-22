# Entry point for Phusion Passenger (cPanel "Setup Python App"): Startup file passenger_wsgi.py, Entry point application
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from praetorian.web import app as application  # noqa: E402
