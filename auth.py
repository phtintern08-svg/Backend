"""
Authentication and Authorization Utilities
Provides JWT token generation, verification, and decorators for route protection
"""
import jwt
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timedelta
from models import Admin, Customer, Vendor, Rider


def generate_token(user_id, role, username=None, email=None, phone=None):
    """
    Generate a JWT token for authenticated user
    
    Args:
        user_id: User ID
        role: User role (admin, customer, vendor, rider)
        username: Optional username
        email: Optional email
        phone: Optional phone
    
    Returns:
        str: JWT token
    """
    payload = {
        'user_id': user_id,
        'role': role,
        'username': username,
        'email': email,
        'phone': phone,
        'exp': datetime.utcnow() + timedelta(days=7),  # Token expires in 7 days
        'iat': datetime.utcnow()
    }
    
    secret_key = current_app.config.get('SECRET_KEY')
    if not secret_key:
        raise ValueError("SECRET_KEY not configured")
    
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    # PyJWT 2.x returns a string, but ensure it's a string for compatibility
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token


def verify_token(token):
    """
    Verify and decode a JWT token
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Decoded token payload or None if invalid
    """
    try:
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            return None
        
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    """
    Get current authenticated user from request token
    
    Returns:
        dict: User information from token or None
    """
    token = get_token_from_request()
    if not token:
        return None
    
    payload = verify_token(token)
    return payload


def get_token_from_request():
    """
    Extract JWT token from request headers
    
    Returns:
        str: Token or None
    """
    # Check Authorization header: Bearer <token>
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            token = auth_header.split(' ')[1]  # Extract token from "Bearer <token>"
            return token
        except IndexError:
            pass
    
    # Fallback: Check for token in request args (for JSONP compatibility)
    token = request.args.get('token')
    if token:
        return token
    
    # Fallback: Check for token in JSON body
    if request.is_json:
        token = request.json.get('token')
        if token:
            return token
    
    return None


def require_auth(f):
    """
    Decorator to require authentication for a route
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
        
        # Add user info to request context
        request.current_user = payload
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific role(s) for a route
    
    Args:
        *allowed_roles: One or more allowed roles (admin, customer, vendor, rider)
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user_role = request.current_user.get('role')
            
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "required_roles": list(allowed_roles),
                    "user_role": user_role
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_self_or_role(user_id_param='user_id', *allowed_roles):
    """
    Decorator to allow access if user is accessing their own resource OR has required role
    
    Args:
        user_id_param: Parameter name in route/kwargs that contains the user ID
        *allowed_roles: Allowed roles for cross-user access
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            current_user_id = request.current_user.get('user_id')
            current_user_role = request.current_user.get('role')
            
            # Get the user_id from route parameters or request data
            target_user_id = kwargs.get(user_id_param)
            if target_user_id is None:
                # Try to get from request JSON
                if request.is_json:
                    target_user_id = request.json.get(user_id_param)
                # Try to get from form data
                if target_user_id is None:
                    target_user_id = request.form.get(user_id_param)
                # Try to get from query params
                if target_user_id is None:
                    target_user_id = request.args.get(user_id_param)
            
            # Convert to int for comparison
            try:
                current_user_id = int(current_user_id)
                if target_user_id:
                    target_user_id = int(target_user_id)
            except (ValueError, TypeError):
                pass
            
            # Allow if accessing own resource or has required role
            if target_user_id and current_user_id == target_user_id:
                return f(*args, **kwargs)
            
            if current_user_role in allowed_roles:
                return f(*args, **kwargs)
            
            return jsonify({
                "error": "Insufficient permissions",
                "code": "INSUFFICIENT_PERMISSIONS"
            }), 403
        
        return decorated_function
    return decorator


def verify_user_exists(user_id, role):
    """
    Verify that the user exists in the database
    
    Args:
        user_id: User ID
        role: User role
    
    Returns:
        bool: True if user exists, False otherwise
    """
    try:
        if role == 'admin':
            user = Admin.query.get(user_id)
        elif role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        elif role == 'rider':
            user = Rider.query.get(user_id)
        else:
            return False
        
        return user is not None
    except Exception:
        return False

