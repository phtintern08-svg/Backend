"""
WSGI Entry Point
Alternative WSGI entry point (can be used if passenger_wsgi.py is not in root)
"""
import sys
import os

# Ensure we're in the right directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Import the Flask application
from app import app as application

# WSGI application object
__all__ = ['application']

