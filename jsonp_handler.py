"""
JSONP Handler for Cross-Origin Requests
Implements JSONP support as preferred over CORS per user requirements
"""
import json
import re
from flask import request, Response
from typing import Optional, Callable
from logger_config import log_warning


# Allowed callback function name pattern (alphanumeric, underscore, dot)
CALLBACK_PATTERN = re.compile(r'^[a-zA-Z0-9_.]+$')


def validate_callback(callback: str) -> bool:
    """
    Validate JSONP callback function name to prevent XSS
    
    Args:
        callback: Callback function name
        
    Returns:
        True if valid, False otherwise
    """
    if not callback:
        return False
    
    # Check length (reasonable limit)
    if len(callback) > 50:
        return False
    
    # Check pattern (alphanumeric, underscore, dot only)
    return bool(CALLBACK_PATTERN.match(callback))


def jsonp_response(data: dict, status_code: int = 200) -> Response:
    """
    Create JSONP response if callback parameter is present
    
    Args:
        data: Data dictionary to return
        status_code: HTTP status code
        
    Returns:
        Flask Response object (JSONP if callback present, JSON otherwise)
    """
    callback = request.args.get('callback') or request.args.get('jsonp')
    
    # If callback is provided and valid, return JSONP
    if callback and validate_callback(callback):
        json_data = json.dumps(data, default=str)
        response_text = f"{callback}({json_data});"
        
        response = Response(
            response_text,
            status=status_code,
            mimetype='application/javascript'
        )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        
        return response
    
    # Otherwise return standard JSON
    response = Response(
        json.dumps(data, default=str),
        status=status_code,
        mimetype='application/json'
    )
    
    return response


def jsonp_enabled() -> bool:
    """
    Check if JSONP is enabled for current request
    
    Returns:
        True if callback parameter is present and valid
    """
    callback = request.args.get('callback') or request.args.get('jsonp')
    return callback and validate_callback(callback)


def jsonp_decorator(f: Callable) -> Callable:
    """
    Decorator to automatically convert JSON responses to JSONP if callback is present
    
    Usage:
        @app.route('/api/data')
        @jsonp_decorator
        def get_data():
            return jsonify({"data": "value"})
    
    Args:
        f: Flask route function
        
    Returns:
        Wrapped function
    """
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Call original function
        result = f(*args, **kwargs)
        
        # If result is a tuple (response, status_code)
        if isinstance(result, tuple) and len(result) == 2:
            response, status_code = result
        else:
            response = result
            status_code = 200
        
        # If response is already a Response object with JSON, convert to JSONP
        if isinstance(response, Response):
            if response.mimetype == 'application/json':
                try:
                    data = json.loads(response.get_data(as_text=True))
                    return jsonp_response(data, status_code)
                except (json.JSONDecodeError, ValueError):
                    return response
            return response
        
        # If response is a dict, convert to JSONP
        if isinstance(response, dict):
            return jsonp_response(response, status_code)
        
        return response
    
    return decorated_function

