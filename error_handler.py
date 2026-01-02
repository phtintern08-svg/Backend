"""
Error Handling Utilities
Provides centralized error handling and logging for production safety
"""
import traceback
from flask import jsonify, request
from config import Config
from logger_config import log_error_with_context, error_logger


def log_error(error, context=None):
    """
    Log error details server-side only
    
    Args:
        error: Exception object
        context: Optional context information (dict)
    """
    # Add request context if available
    if context is None:
        context = {}
    
    try:
        if request:
            context['endpoint'] = request.path
            context['method'] = request.method
            context['remote_addr'] = request.remote_addr
    except Exception:
        pass
    
    # Use structured logging
    log_error_with_context(error, context)


def get_error_message(error, default_message="An error occurred"):
    """
    Get appropriate error message based on environment
    
    Args:
        error: Exception object
        default_message: Default message to return in production
    
    Returns:
        str: Error message (detailed in dev, generic in production)
    """
    if Config.ENV == 'production':
        # In production, return generic messages
        error_type = type(error).__name__
        
        # Map specific error types to user-friendly messages
        if 'IntegrityError' in error_type or 'Duplicate' in str(error):
            return "This record already exists. Please check your input."
        elif 'OperationalError' in error_type or 'Database' in error_type:
            return "Database operation failed. Please try again later."
        elif 'ValidationError' in error_type:
            return "Invalid input provided. Please check your data."
        elif 'PermissionError' in error_type or 'Forbidden' in error_type:
            return "You don't have permission to perform this action."
        elif 'NotFound' in error_type or '404' in str(error):
            return "The requested resource was not found."
        else:
            return default_message
    else:
        # In development, return detailed messages
        return f"{type(error).__name__}: {str(error)}"


def handle_exception(error, context=None, default_message="An error occurred"):
    """
    Handle exception and return appropriate response
    
    Args:
        error: Exception object
        context: Optional context information
        default_message: Default message for production
    
    Returns:
        tuple: (jsonify response, status_code)
    """
    # Log error details server-side
    log_error(error, context)
    
    # Get appropriate error message
    error_message = get_error_message(error, default_message)
    
    # Determine status code
    error_type = type(error).__name__
    if 'NotFound' in error_type or '404' in str(error):
        status_code = 404
    elif 'ValidationError' in error_type or 'ValueError' in error_type:
        status_code = 400
    elif 'PermissionError' in error_type or 'Forbidden' in error_type or '403' in str(error):
        status_code = 403
    elif 'Unauthorized' in error_type or '401' in str(error):
        status_code = 401
    else:
        status_code = 500
    
    return jsonify({"error": error_message}), status_code


def safe_execute(func, default_message="An error occurred", context=None):
    """
    Decorator-like function to safely execute code with error handling
    
    Args:
        func: Function to execute
        default_message: Default error message
        context: Optional context information
    
    Returns:
        Result of func or error response
    """
    try:
        return func()
    except Exception as e:
        return handle_exception(e, context, default_message)

