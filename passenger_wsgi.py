"""
Passenger WSGI Entry Point for cPanel - PRODUCTION ONLY
This file is used by cPanel's Passenger application server to run the Flask application
"""
import sys
import os

# Determine the correct path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(current_dir, 'Backend')

# Add the Backend directory to Python path
if os.path.exists(backend_dir):
    sys.path.insert(0, backend_dir)
    os.chdir(backend_dir)
else:
    # If already in Backend directory
    sys.path.insert(0, current_dir)
    os.chdir(current_dir)


try:
    from app import application
except ImportError:
    # Fallback: try importing app and getting application
    try:
        from app import app as application
    except ImportError:
        # Last fallback: import module and get application
        import app
        application = app.application if hasattr(app, 'application') else app.app


