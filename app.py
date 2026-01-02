from flask import Flask, request, jsonify, send_from_directory, send_file
from datetime import datetime, timedelta
import os
import json
from dotenv import load_dotenv

load_dotenv()
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from wtforms.csrf.session import SessionCSRF
import requests
from config import Config
import openpyxl
import csv
import io
import math
from models import (
    db,
    Admin,
    Customer,
    Vendor,
    VendorDocument,
    VendorQuotationSubmission,
    RiderDocument,
    Address,
    Order,
    VendorQuotation,
    ProductCatalog,
    Payment,  # Admin Payment (with transaction_id)
    CustomerPayment,  # Customer Payment (with payer_type, receiver_type)
    Notification,
    Category,
    Thread,
    Comment,
    DeliveryPartner,
    Rider,
    DeliveryLog,
    OTPLog,
    VendorOrderAssignment,
    OrderStatusHistory,
)
from schemas import (
    ma,
    customer_schema,
    customers_schema,
    vendor_schema,
    vendors_schema,
    address_schema,
    addresses_schema,
    order_schema,
    orders_schema,
    vendor_quotation_schema,
    vendor_quotations_schema,
    payment_schema,
    payments_schema,
    category_schema,
    categories_schema,
    thread_schema,
    threads_schema,
    comment_schema,
    comments_schema,
    delivery_partner_schema,
    rider_schema,
    riders_schema,
    otp_log_schema,
    otp_logs_schema,
)

from werkzeug.middleware.proxy_fix import ProxyFix
from auth import (
    generate_token,
    verify_token,
    require_auth,
    require_role,
    require_self_or_role,
    get_current_user
)
from error_handler import handle_exception, log_error, get_error_message
from logger_config import (
    app_logger,
    error_logger,
    access_logger,
    auth_logger,
    log_request,
    log_auth_event,
    log_info,
    log_warning
)
from validation import (
    validate_request_data,
    sanitize_html,
    sanitize_text,
    LoginSchema,
    RegisterSchema,
    AddressSchema,
    OrderSchema,
    ProfileUpdateSchema,
    CommentSchema
)
from file_upload import validate_and_save_file, delete_file
from jsonp_handler import jsonp_response, jsonp_enabled, jsonp_decorator

# Configure Flask with proper static file serving
# Updated to new folder structure: apparels.impromptuindian.com
app = Flask(__name__, static_folder='../Frontend/apparels.impromptuindian.com', static_url_path='')
app.url_map.strict_slashes = False
app.config.from_object(Config)

# Apply ProxyFix for proper header handling (X-Forwarded-Proto, etc.) behind Nginx/ELB
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Use absolute path for uploads
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, '../Frontend/apparels.impromptuindian.com/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Flask-Mail Configuration (all values from environment in production)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER') or app.config['MAIL_USERNAME']
app.config['MAIL_TIMEOUT'] = 5  # 5 second timeout for email
app.config['MAIL_USE_SSL'] = False

# MSG91 Configuration (SMS Gateway for India) - DISABLED
# Sign up at https://msg91.com to get your Authkey
# Get Authkey from: Dashboard -> API -> Authkey
# Use Config values to avoid duplication
# MSG91_AUTHKEY = Config.MSG91_AUTHKEY
# MSG91_SENDER_ID = Config.MSG91_SENDER_ID
MSG91_AUTHKEY = None
MSG91_SENDER_ID = None

# Initialize extensions
# Database initialization with improved connection pooling (configured in config.py)
db.init_app(app)
ma.init_app(app)
mail = Mail(app)

# Import database connection utilities for health checks
from db_connection import check_database_health, get_pool_status

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
# Use IP address for rate limiting (works behind proxy with ProxyFix)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Use in-memory storage (can be changed to Redis in production)
    strategy="fixed-window"  # Use fixed window strategy
)

# Custom key function for OTP rate limiting by recipient (phone/email)
def get_otp_recipient():
    """Get recipient from request for OTP rate limiting"""
    try:
        if request.is_json:
            recipient = request.get_json().get('recipient')
            if recipient:
                return f"otp:{recipient}"
    except Exception:
        pass
    # Fallback to IP address if recipient not found
    return get_remote_address()

# Request Logging Middleware
@app.before_request
def log_request_start():
    """Log request start time"""
    from time import time
    request.start_time = time()

# Response Logging Middleware
@app.after_request
def log_request_end(response):
    """Log request completion"""
    duration = None
    if hasattr(request, 'start_time'):
        from time import time
        duration = time() - request.start_time
    
    log_request(request, response, duration)
    return response

# CSP Headers Middleware
# JSONP Support - Convert JSON responses to JSONP if callback parameter is present
@app.after_request
def handle_jsonp(response):
    """Automatically convert JSON responses to JSONP if callback parameter is present"""
    # Only process JSON responses
    if response.mimetype == 'application/json':
        callback = request.args.get('callback') or request.args.get('jsonp')
        
        if callback and jsonp_enabled():
            try:
                # Get JSON data
                data = json.loads(response.get_data(as_text=True))
                # Return JSONP response
                return jsonp_response(data, response.status_code)
            except (json.JSONDecodeError, ValueError):
                # If JSON parsing fails, return original response
                pass
    
    return response

@app.after_request
def set_security_headers(response):
    """Add security headers including CSP to all responses"""
    # Content Security Policy
    csp_policy = (
        f"default-src {Config.CSP_DEFAULT_SRC}; "
        f"script-src {Config.CSP_SCRIPT_SRC}; "
        f"style-src {Config.CSP_STYLE_SRC}; "
        f"img-src {Config.CSP_IMG_SRC}; "
        f"font-src {Config.CSP_FONT_SRC}; "
        f"connect-src {Config.CSP_CONNECT_SRC}; "
        f"frame-ancestors {Config.CSP_FRAME_ANCESTORS}; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (only in production with HTTPS)
    if Config.ENV == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# CORS Configuration (JSONP is preferred for cross-origin, CORS as fallback)
# JSONP support is implemented via jsonp_handler.py
# CORS is kept for browsers that don't support JSONP or for same-origin requests
if Config.ENV == 'production':
    # In production, restrict CORS to allowed origins only
    # JSONP will handle cross-origin requests via callback parameter
    CORS(app, 
         resources={r"/*": {"origins": Config.ALLOWED_ORIGINS}},
         supports_credentials=False,  # JSONP doesn't support credentials
         allow_headers=["Content-Type", "Authorization", "X-CSRFToken"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         expose_headers=["Content-Type"])
else:
    # Allow all origins in development (for testing)
    CORS(app, 
         allow_headers=["Content-Type", "Authorization", "X-CSRFToken"],
         expose_headers=["Content-Type"])

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, '../Frontend/apparels.impromptuindian.com/images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Validate environment variables on startup
if Config.ENV == 'production':
    from validate_env import validate_environment
    is_valid, missing_vars, warnings = validate_environment()
    if not is_valid:
        error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
        print(f"\n{'='*60}")
        print("ERROR: Environment validation failed!")
        print(f"{'='*60}")
        print(error_msg)
        print("\nPlease set all required variables. See env.example for reference.")
        print(f"{'='*60}\n")
        raise ValueError(error_msg)
    if warnings:
        for warning in warnings:
            log_warning(f"Environment variable warning: {warning}")

# Create tables before first request
with app.app_context():
    db.create_all()
    
    # Create default admin only in development environment
    # In production, admin must be created manually or via environment variables
    if Config.ENV == 'development':
        default_username = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin@gmail.com')
        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin')
        
        if not Admin.query.filter_by(username=default_username).first():
            default_admin = Admin(
                username=default_username,
                password_hash=generate_password_hash(default_password)
            )
            db.session.add(default_admin)
            db.session.commit()
            log_info(f"Default admin created (DEV ONLY): {default_username}", {"environment": "development"})
    else:
        # Production: Check for initial admin from environment variables
        initial_admin_username = os.environ.get('INITIAL_ADMIN_USERNAME')
        initial_admin_password = os.environ.get('INITIAL_ADMIN_PASSWORD')
        
        if initial_admin_username and initial_admin_password:
            if not Admin.query.filter_by(username=initial_admin_username).first():
                initial_admin = Admin(
                    username=initial_admin_username,
                    password_hash=generate_password_hash(initial_admin_password)
                )
                db.session.add(initial_admin)
                db.session.commit()
                log_info(f"Initial admin created from environment variables: {initial_admin_username}", {"environment": "production"})
                # Clear environment variables after use for security
                os.environ.pop('INITIAL_ADMIN_USERNAME', None)
                os.environ.pop('INITIAL_ADMIN_PASSWORD', None)

import random
import time
import sys
import threading
import urllib.parse

# In-memory storage for OTPs (for demonstration purposes only)
# Structure: { recipient: (otp, expires_at_timestamp) }
otp_storage = {}
OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', '600'))  # default 10 minutes

# Helper function to build URLs dynamically based on environment
def build_subdomain_url(subdomain, path='', query_params=None):
    """
    Build a URL for a subdomain based on environment configuration.
    
    Args:
        subdomain: Subdomain name (e.g., 'vendor', 'rider')
        path: Optional path to append (e.g., '/dashboard')
        query_params: Optional dict of query parameters
    
    Returns:
        str: Complete URL (https in production, http in development)
    """
    import urllib.parse
    
    # Determine scheme based on environment
    scheme = 'https' if Config.ENV == 'production' else 'http'
    
    # Get base domain from config
    base_domain = Config.BASE_DOMAIN
    
    # Build subdomain host
    if subdomain:
        # Extract domain and port from BASE_DOMAIN
        if ':' in base_domain:
            domain, port = base_domain.split(':', 1)
            subdomain_domain = f"{subdomain}.{domain}"
            # In production, don't include port (assumes standard ports 80/443)
            if Config.ENV == 'production':
                host = subdomain_domain
            else:
                # In development, preserve the port
                host = f"{subdomain_domain}:{port}"
        else:
            # No port specified in BASE_DOMAIN
            subdomain_domain = f"{subdomain}.{base_domain}"
            host = subdomain_domain
    else:
        # No subdomain - use base domain as-is
        # In production, remove port if present (assumes standard ports)
        if Config.ENV == 'production' and ':' in base_domain:
            host = base_domain.split(':')[0]
        else:
            host = base_domain
    
    # Ensure path starts with / if provided
    if path and not path.startswith('/'):
        path = '/' + path
    
    # Build URL
    url = f"{scheme}://{host}{path}"
    
    # Add query parameters if provided
    if query_params:
        query_string = urllib.parse.urlencode(query_params)
        url = f"{url}?{query_string}"
    
    return url

@app.route('/api/config', methods=['GET'])
@require_auth
def get_config():
    """Get application configuration including API keys for frontend"""
    try:
        # Get Mappls API key from environment (for map services)
        mappls_key = os.environ.get('MAPPLS_API_KEY', '')
        
        return jsonify({
            "hereApiKey": os.environ.get('HERE_API_KEY') or "YOUR_HERE_API_KEY",
            "mapplsApiKey": os.environ.get('MAPPLS_API_KEY') or ""
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# MSG91 Config Endpoint - DISABLED
# @app.route('/api/msg91-config', methods=['GET'])
# @csrf.exempt  # Public endpoint for OTP widget
# def get_msg91_config():
#     """Get MSG91 OTP widget configuration"""
#     try:
#         widget_id = Config.MSG91_WIDGET_ID
#         token_auth = Config.MSG91_TOKEN_AUTH
#         
#         if not widget_id or not token_auth:
#             return jsonify({
#                 "error": "MSG91 widget credentials not configured. Please set MSG91_WIDGET_ID and MSG91_TOKEN_AUTH in environment variables."
#             }), 500
#         
#         return jsonify({
#             "widgetId": widget_id,
#             "tokenAuth": token_auth
#         }), 200
#     except Exception as e:
#         return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

def _perform_mappls_reverse_geocode(lat, lng):
    """Helper to fetch human-readable address from MapmyIndia"""
    api_key = os.environ.get('MAPPLS_API_KEY')
    if not api_key:
        raise ValueError("MAPPLS_API_KEY environment variable is required")
    url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/rev_geocode?lat={lat}&lng={lng}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data and 'results' in data and len(data['results']) > 0:
                return data['results'][0].get('formatted_address', 'Unknown Address')
            return "Address not found"
        return f"Error: {response.status_code}"
    except Exception as e:
        return "Service unavailable"

@app.route('/api/reverse-geocode', methods=['GET'])
@require_auth
def reverse_geocode():
    lat = request.args.get('lat')
    lng = request.args.get('lng')

    if not lat or not lng:
        return jsonify({"error": "Latitude and longitude required"}), 400

    api_key = os.environ.get('MAPPLS_API_KEY')
    if not api_key:
        return jsonify({"error": "MAPPLS_API_KEY environment variable is required"}), 500
    url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/rev_geocode?lat={lat}&lng={lng}"

    try:
        response = requests.get(url)
        if response.status_code != 200:
             return jsonify({"error": "Failed to fetch from MapmyIndia"}), response.status_code
        
        return jsonify(response.json()), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/api/geocode', methods=['GET'])
@require_auth
def geocode():
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Query parameter required"}), 400

    # 🚨 KEY CONFIGURATION REQURIED 🚨
    # Requires "Client ID" and "Client Secret" from Dashboard -> Keys -> Oauth/Security
    # If not set, users often only have the cryptic REST key which fails 412.
    # FALLBACK: We will try to fetch a public token if secret is missing (risky but often works)
    
    # API Key must be set in environment variables for security
    # If the key is failing REST calls (412), try a different endpoint strategy
    # Strategy C: The "AutoSuggest" API *requires* specific headers OR is domain locked 
    
    api_key = os.environ.get('MAPPLS_API_KEY')
    if not api_key:
        return jsonify({"error": "MAPPLS_API_KEY environment variable is required"}), 500

    # TRY 1: ADD REFERER HEADER (Dynamic for Production)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': request.host_url,
        'Origin': request.host_url.rstrip('/')
    }
    
    autosuggest_url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/autosuggest?query={query}"
    
    try:
        response = requests.get(autosuggest_url, headers=headers, timeout=10)
        if response.status_code == 200:
             data = response.json()
             if 'suggestedLocations' in data:
                return jsonify({"copResults": data['suggestedLocations']}), 200
             return jsonify(data), 200
    except (requests.RequestException, ValueError) as e:
        pass  # Try next endpoint

    # TRY 2: GEOCODE API (Different Endpoint)
    geo_url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/geo_code?addr={query}"
    try:
        response = requests.get(geo_url, headers=headers, timeout=10)
        if response.status_code == 200:
             return jsonify(response.json()), 200
    except (requests.RequestException, ValueError):
        pass  # Try next endpoint
        
    # TRY 3: ELOC API (If they searched an eLoc?)
    # ...
    
    return jsonify({"error": f"MapmyIndia Search Failed (412). Check usage limits or domain whitelist."}), 412

# ----------------------------------------------------------------
# ROUTING & SUBDOMAIN MAPPING
# ----------------------------------------------------------------

# Test route to verify static files

# Explicitly serve static files for subdomains with fallback logic
def serve_static_for_subdomain(subdomain, folder, filename):
    # Map subdomain to new folder structure
    if subdomain == 'vendor':
        sub_folder_name = 'vendor.impromptuindian.com'
    elif subdomain == 'rider':
        sub_folder_name = 'rider.impromptuindian.com'
    else:
        sub_folder_name = 'apparels.impromptuindian.com'
    
    # 1. Try subdomain-specific folder first (e.g., Frontend/vendor.impromptuindian.com/css/dashboard.css)
    try:
        path = os.path.join(BASE_DIR, f'../Frontend/{sub_folder_name}/{folder}')
        if os.path.exists(os.path.join(path, filename)):
             return send_from_directory(path, filename)
    except Exception:
        pass
        
    # 2. Fallback to main app folder (e.g., Frontend/apparels.impromptuindian.com/css/index.css)
    return send_from_directory(f'../Frontend/apparels.impromptuindian.com/{folder}', filename)

for sub in ['vendor', 'rider']:
    # CSS
    app.add_url_rule(f'/css/<path:filename>', 
                     endpoint=f'css_{sub}', 
                     view_func=lambda filename, s=sub: serve_static_for_subdomain(s, 'css', filename), 
                     subdomain=sub)
    # JS
    app.add_url_rule(f'/js/<path:filename>', 
                     endpoint=f'js_{sub}', 
                     view_func=lambda filename, s=sub: serve_static_for_subdomain(s, 'js', filename), 
                     subdomain=sub)
    # Images
    app.add_url_rule(f'/images/<path:filename>', 
                     endpoint=f'images_{sub}', 
                     view_func=lambda filename, s=sub: serve_static_for_subdomain(s, 'images', filename), 
                     subdomain=sub)

# --- VENDOR SUBDOMAIN ---

@app.route("/", subdomain="vendor")
def vendor_home():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "home.html")

@app.route("/login", subdomain="vendor")
def vendor_login():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "login.html")

@app.route("/verification", subdomain="vendor")
def vendor_verification():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "verification.html")

@app.route("/new-orders", subdomain="vendor")
def vendor_new_orders():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "new-orders.html")

@app.route("/accepted-orders", subdomain="vendor")
def vendor_accepted_orders():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "accepted-orders.html")

@app.route("/production", subdomain="vendor")
def vendor_production():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "production.html")

@app.route("/inventory", subdomain="vendor")
def vendor_inventory():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "inventory.html")

@app.route("/payments", subdomain="vendor")
def vendor_payments():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "payments.html")

@app.route("/earnings", subdomain="vendor")
def vendor_earnings():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "earnings.html")

@app.route("/reports", subdomain="vendor")
def vendor_reports():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "reports.html")

@app.route("/support", subdomain="vendor")
def vendor_support():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "support.html")

@app.route("/settings", subdomain="vendor")
def vendor_settings():
    return send_from_directory("../Frontend/vendor.impromptuindian.com", "settings.html")

# Serve shared login page with .html extension
@app.route("/login.html", subdomain="vendor")
def vendor_login_html():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "login.html")

# Generic handler for .html pages in vendor subdomain
@app.route('/<path:page>.html', subdomain="vendor")
def serve_vendor_html(page):
    return send_from_directory('../Frontend/vendor.impromptuindian.com', f'{page}.html')


# --- RIDER SUBDOMAIN ---

@app.route("/", subdomain="rider")
def rider_home():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "home.html")

@app.route("/login", subdomain="rider")
def rider_login():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "login.html")

@app.route("/verification", subdomain="rider")
def rider_verification():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "verification.html")

@app.route("/assigned-deliveries", subdomain="rider")
def rider_assigned_deliveries():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "assigned-deliveries.html")

@app.route("/delivery-history", subdomain="rider")
def rider_delivery_history():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "delivery-history.html")

@app.route("/earnings", subdomain="rider")
def rider_earnings():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "earnings.html")

@app.route("/notifications", subdomain="rider")
def rider_notifications():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "notifications.html")

@app.route("/profile", subdomain="rider")
def rider_profile():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "profile.html")

# ==========================================
# STATIC FILE SERVING (EXPLICIT HANDLERS)
# ==========================================

# --- Main Domain Static ---
@app.route('/css/<path:filename>')
def serve_main_css(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/css', filename)

@app.route('/js/<path:filename>')
def serve_main_js(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/js', filename)

@app.route('/customer/css/<path:filename>')
def serve_customer_css(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/customer/css', filename)

@app.route('/customer/js/<path:filename>')
def serve_customer_js(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/customer/js', filename)

@app.route('/customer/models/<path:filename>')
def serve_customer_models(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/customer/models', filename)

@app.route('/admin/css/<path:filename>')
def serve_admin_css(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/admin/css', filename)

@app.route('/admin/js/<path:filename>')
def serve_admin_js(filename):
    return send_from_directory('../Frontend/apparels.impromptuindian.com/admin/js', filename)

@app.route('/admin/assign-vendor', methods=['POST'])
@require_role('admin')
def admin_assign_vendor():
    """Admin assigns a vendor to an order from the New Orders page"""
    data = request.json
    order_id = data.get('order_id')
    vendor_id = data.get('vendor_id')
    
    if not order_id or not vendor_id:
        return jsonify({"error": "Missing order_id or vendor_id"}), 400
        
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
            
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
            
        order.selected_vendor_id = vendor_id
        # Update status to assigned
        order.status = 'assigned'
        
        # Create or update formal assignment record
        assignment = VendorOrderAssignment.query.filter_by(order_id=order_id, vendor_id=vendor_id).first()
        if not assignment:
            assignment = VendorOrderAssignment(
                order_id=order_id,
                vendor_id=vendor_id,
                status='pending'
            )
            db.session.add(assignment)
        else:
            assignment.status = 'pending'
            assignment.assigned_at = datetime.utcnow()
            assignment.responded_at = None
        
        # Create notification for vendor
        notif = Notification(
            user_id=vendor_id,
            user_type='vendor',
            title='New Order Assigned',
            message=f'Admin has assigned a new order #{order_id} to you.',
            type='order'
        )
        db.session.add(notif)
        
        # Record status history for tracking
        status_record = OrderStatusHistory(
            order_id=order_id,
            status='assigned',
            status_label='Vendor Assigned',
            changed_by_type='admin',
            changed_by_id=1,  # Admin ID
            notes=f'Assigned to vendor: {vendor.business_name or vendor.username}'
        )
        db.session.add(status_record)
        
        db.session.commit()
        
        return jsonify({
            "message": f"Order #{order_id} successfully assigned to {vendor.business_name or vendor.username}",
            "order_id": order_id,
            "vendor_id": vendor_id,
            "status": "assigned"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# --- Subdomain Static (Vendor) ---
@app.route('/css/<path:filename>', subdomain='vendor')
def serve_vendor_css(filename):
    return send_from_directory('../Frontend/vendor.impromptuindian.com/css', filename)

@app.route('/js/<path:filename>', subdomain='vendor')
def serve_vendor_js(filename):
    return send_from_directory('../Frontend/vendor.impromptuindian.com/js', filename)

# --- Subdomain Static (Rider) ---
@app.route('/css/<path:filename>', subdomain='rider')
def serve_rider_css(filename):
    return send_from_directory('../Frontend/rider.impromptuindian.com/css', filename)

@app.route('/js/<path:filename>', subdomain='rider')
def serve_rider_js(filename):
    return send_from_directory('../Frontend/rider.impromptuindian.com/js', filename)

# --- Shared Resources (Images, Uploads, JS) - All Domains ---
for sub in [None, 'vendor', 'rider']:
    suffix = f"_{sub}" if sub else "_main"
    
    @app.route('/images/<path:filename>', subdomain=sub, endpoint=f'serve_images{suffix}')
    def serve_images(filename):
        return send_from_directory('../Frontend/apparels.impromptuindian.com/images', filename)

    @app.route('/uploads/<path:filename>', subdomain=sub, endpoint=f'serve_uploads{suffix}')
    def serve_uploads(filename):
        return send_from_directory('../Frontend/apparels.impromptuindian.com/uploads', filename)
    
    # Serve shared JS files from main app for subdomains
    @app.route('/shared-js/<path:filename>', subdomain=sub, endpoint=f'serve_shared_js{suffix}')
    def serve_shared_js(filename):
        return send_from_directory('../Frontend/apparels.impromptuindian.com/js', filename)



@app.route("/support", subdomain="rider")
def rider_support():
    return send_from_directory("../Frontend/rider.impromptuindian.com", "support.html")

# Serve shared login page with .html extension
@app.route("/login.html", subdomain="rider")
def rider_login_html():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "login.html")

# Generic handler for .html pages in rider subdomain
@app.route('/<path:page>.html', subdomain="rider")
def serve_rider_html(page):
    return send_from_directory('../Frontend/rider.impromptuindian.com', f'{page}.html')


# --- MAIN DOMAIN (apparels.impromptuindian.com) ---

# Root landing page with portal selection
@app.route("/")
def index():
    return send_from_directory("../Frontend", "index.html")

# Main app index page
@app.route("/apparels")
def apparels_index():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "index.html")

# Serve any .html file directly to support legacy links (e.g. login.html)
@app.route('/<path:page>.html')
def serve_html_pages(page):
    return send_from_directory('../Frontend/apparels.impromptuindian.com', f'{page}.html')

@app.route("/about")
def about():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "about.html")

@app.route("/blog")
def blog():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "blog.html")

@app.route("/support")
def support():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "support.html")

@app.route("/terms")
def terms():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "terms.html")

@app.route("/login") # GET request for page, POST is handled by API
def login_page():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "login.html")

@app.route("/register")
def register():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "register.html")

@app.route("/otp")
def otp():
    return send_from_directory("../Frontend/apparels.impromptuindian.com", "otp.html")

# Customer Pages
@app.route("/customer/home")
def customer_home():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "home.html")

@app.route("/customer/products")
def customer_products():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "products.html")

@app.route("/customer/new-order")
def customer_new_order():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "new-order.html")

@app.route("/customer/cart")
def customer_cart():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "cart.html")

@app.route("/customer/orders")
def customer_orders():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "orders.html")

@app.route("/customer/profile")
def customer_profile():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "profile.html")

@app.route("/customer/settings")
def customer_settings():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "settings.html")

@app.route("/customer/support")
def customer_support_page():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "support.html")

@app.route("/customer/feedback")
def customer_feedback():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/customer", "feedback.html")

# Admin Pages
@app.route("/admin/home")
def admin_home():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "home.html")

@app.route("/admin/vendors")
def admin_vendors():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "vendors.html")

@app.route("/admin/riders")
def admin_riders():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "riders.html")

@app.route("/admin/orders")
def admin_orders():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "orders.html")

@app.route("/admin/payments")
def admin_payments():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "payments.html")

@app.route("/admin/reports")
def admin_reports():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "reports.html")

@app.route("/admin/settings")
def admin_settings():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "settings.html")

@app.route("/admin/view-otp-logs")
def admin_otp_logs_page():
    return send_from_directory("../Frontend/apparels.impromptuindian.com/admin", "otp-logs.html")

@app.route('/send-otp', methods=['POST'])
@limiter.limit("3 per hour", key_func=get_otp_recipient)
@csrf.exempt  # Public endpoint
def send_otp():
    try:
        data = request.get_json()
        recipient = data.get('recipient') if data else None
        type_ = data.get('type') if data else None
        
        if not recipient or not type_:
            return jsonify({"error": "Recipient and type required"}), 400
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Store OTP with expiry
        expires_at = time.time() + OTP_TTL_SECONDS
        otp_storage[recipient] = (otp, expires_at)
        
        # Save OTP to Database
        try:
            new_otp_log = OTPLog(
                recipient=recipient,
                otp_code=otp,
                type=type_,
                status='sent',
                created_at=datetime.utcnow(),
                expires_at=datetime.fromtimestamp(expires_at)
            )
            db.session.add(new_otp_log)
            db.session.commit()
        except Exception as db_err:
            db.session.rollback()

        try:
            if type_ == 'email':
                # Send email in background thread to avoid blocking
                def send_email_async():
                    try:
                        with app.app_context():
                            msg = Message(
                                subject='Your Threadly OTP Code',
                                recipients=[recipient],
                                body=f'Your OTP code is: {otp}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this code, please ignore this email.'
                            )
                            mail.send(msg)
                    except Exception:
                        pass  # Email sending failed, but don't block the response
                
                # Start email thread (non-blocking)
                email_thread = threading.Thread(target=send_email_async)
                email_thread.daemon = True
                email_thread.start()

            # Phone OTP via MSG91 - DISABLED
            # elif type_ == 'phone':
            #     # Send SMS using MSG91 API (India)
            #     if MSG91_AUTHKEY:
            #         try:
            #             # Clean phone number (remove +91, spaces, dashes)
            #             clean_phone = recipient.replace('+91', '').replace(' ', '').replace('-', '')
            #             
            #             # Ensure phone number is 10 digits (Indian format)
            #             if len(clean_phone) == 10:
            #                 clean_phone = '91' + clean_phone
            #             elif not clean_phone.startswith('91'):
            #                 clean_phone = '91' + clean_phone.lstrip('0')
            #             
            #             # Prepare the message
            #             message = f"Your ImpromptuIndian verification code is {otp}. Valid for 10 minutes."
            #             
            #             # MSG91 Send HTTP API endpoint (for transactional SMS)
            #             url = "https://control.msg91.com/api/sendhttp.php"
            #             
            #             # MSG91 API parameters
            #             params = {
            #                 "authkey": MSG91_AUTHKEY,
            #                 "mobiles": clean_phone,
            #                 "message": message,
            #                 "sender": MSG91_SENDER_ID,
            #                 "route": Config.MSG91_ROUTE,  # Configurable route (default: 4 for transactional)
            #                 "country": "91",  # India country code
            #             }
            #             
            #             # Add DLT Template ID if configured
            #             if Config.MSG91_DLT_TE_ID:
            #                 params["DLT_TE_ID"] = Config.MSG91_DLT_TE_ID
            #             
            #             # Send SMS using MSG91 API
            #             response = requests.get(url, params=params, timeout=10)
            #             
            #             # Check response
            #             if response.status_code == 200:
            #                 response_text = response.text.strip()
            #                 # MSG91 returns request ID on success (numeric string)
            #                 if response_text.isdigit():
            #                     log_info(f"MSG91 SMS sent successfully to {recipient}", {
            #                         "otp_sent": True,
            #                         "request_id": response_text
            #                     })
            #                 else:
            #                     # Error response from MSG91
            #                     log_warning(f"MSG91 SMS error: {response_text}", {"recipient": recipient})
            #             else:
            #                 log_warning(f"MSG91 SMS failed with status {response.status_code}", {"recipient": recipient})
            #                 
            #         except requests.RequestException as e:
            #             log_error(e, {"recipient": recipient, "error_type": "MSG91_API_REQUEST_FAILED"})
            #         except Exception as e:
            #             log_error(e, {"recipient": recipient, "error_type": "MSG91_SMS_SENDING_ERROR"})
            #     else:
            #         log_warning("MSG91_AUTHKEY not configured, OTP generated but SMS not sent", {"recipient": recipient})
            #     # OTP is still generated and stored even if SMS fails
            elif type_ == 'phone':
                # Phone OTP is disabled - return error
                return jsonify({"error": "Phone OTP authentication is currently disabled. Please use email for OTP verification."}), 400
        
            return jsonify({"message": f"OTP sent successfully to {recipient}"}), 200
        except Exception:
            # Still return success since OTP is generated
            return jsonify({"message": f"OTP sent successfully to {recipient}"}), 200
            
    except Exception as e:
        return jsonify({"error": "Failed to send OTP. Please check server configuration."}), 500

@app.route('/verify-otp', methods=['POST'])
@limiter.limit("10 per hour")
@csrf.exempt  # Public endpoint
def verify_otp():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        recipient = data.get('recipient')
        otp = data.get('otp')
        
        if not recipient or not otp:
            return jsonify({"error": "Recipient and OTP required"}), 400
        
        stored = otp_storage.get(recipient)

        if not stored:
            return jsonify({"error": "No OTP found for this recipient. Please request a new one."}), 400

        stored_otp, expires_at = stored

        # Check expiration
        if time.time() > expires_at:
            del otp_storage[recipient]
            return jsonify({"error": "OTP has expired. Please request a new one."}), 400
        
        if stored_otp == otp:
            # OTP is correct, remove it from storage
            del otp_storage[recipient]
            return jsonify({"message": "OTP verified successfully", "verified": True}), 200
        else:
            return jsonify({"error": "Invalid OTP. Please try again.", "verified": False}), 400
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")



# Helper function to check for duplicates
def check_duplicate_email_phone(email, phone):
    """Check if email or phone already exists in Customer, Vendor, DeliveryPartner, or Rider table"""
    errors = []
    
    # Check email in all tables
    if email:
        customer_with_email = Customer.query.filter_by(email=email).first()
        vendor_with_email = Vendor.query.filter_by(email=email).first()
        dp_with_email = DeliveryPartner.query.filter_by(email=email).first()
        rider_with_email = Rider.query.filter_by(email=email).first()
        
        if customer_with_email or vendor_with_email or dp_with_email or rider_with_email:
            errors.append("Email already exists")
    
    # Check phone in all tables
    if phone:
        customer_with_phone = Customer.query.filter_by(phone=phone).first()
        vendor_with_phone = Vendor.query.filter_by(phone=phone).first()
        dp_with_phone = DeliveryPartner.query.filter_by(phone=phone).first()
        rider_with_phone = Rider.query.filter_by(phone=phone).first()
        
        if customer_with_phone or vendor_with_phone or dp_with_phone or rider_with_phone:
            errors.append("Phone number already exists")
    
    
    return errors


@app.route('/admin/otp-logs', methods=['GET'])
@require_role('admin')
def get_otp_logs():
    otp_logs = OTPLog.query.order_by(OTPLog.created_at.desc()).limit(100).all()
    return otp_logs_schema.jsonify(otp_logs)

@app.route('/admin/system-stats', methods=['GET'])
@require_role('admin')
def get_system_stats():
    """Get system resource usage statistics for this Flask process only"""
    try:
        import psutil
        import os
        
        # Get current process
        process = psutil.Process(os.getpid())
        
        # CPU Usage for this process
        cpu_percent = process.cpu_percent(interval=1)
        
        # RAM Usage for this process
        memory_info = process.memory_info()
        ram_used_mb = memory_info.rss / (1024 ** 2)  # Convert to MB
        
        # Get system total RAM for percentage calculation
        system_memory = psutil.virtual_memory()
        ram_percent = (memory_info.rss / system_memory.total) * 100
        
        # Network I/O for this process
        try:
            io_counters = process.io_counters()
            bytes_read = io_counters.read_bytes / (1024 ** 2)  # MB
            bytes_written = io_counters.write_bytes / (1024 ** 2)  # MB
        except (AttributeError, NotImplementedError):
            # Some systems don't support per-process I/O stats
            bytes_read = 0
            bytes_written = 0
        
        # Number of threads
        num_threads = process.num_threads()
        
        # Process uptime
        create_time = process.create_time()
        uptime_seconds = time.time() - create_time
        uptime_hours = uptime_seconds / 3600
        
        return jsonify({
            'cpu': {
                'percent': round(cpu_percent, 1),
                'cores': psutil.cpu_count()
            },
            'ram': {
                'percent': round(ram_percent, 2),
                'used_mb': round(ram_used_mb, 2),
                'total_system_gb': round(system_memory.total / (1024 ** 3), 2)
            },
            'io': {
                'read_mb': round(bytes_read, 2),
                'written_mb': round(bytes_written, 2),
                'total_mb': round(bytes_read + bytes_written, 2)
            },
            'process': {
                'threads': num_threads,
                'uptime_hours': round(uptime_hours, 2),
                'pid': os.getpid()
            }
        }), 200
    except ImportError:
        return jsonify({
            'error': 'psutil library not installed. Run: pip install psutil'
        }), 500
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# --- Customer & Vendor Registration Endpoints ---

@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
@csrf.exempt  # Public endpoint - CSRF handled via JWT tokens after registration
def register_user():
    # Validate input data
    data = request.get_json() or {}
    validated_data, errors = validate_request_data(RegisterSchema, data)
    
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400
    
    username = validated_data['username']
    email = validated_data['email']
    password = validated_data['password']
    phone = validated_data['phone']
    role = validated_data.get('role', 'customer')
    business_name = validated_data.get('business_name')
    
    # Check for duplicates across both tables
    duplicate_errors = check_duplicate_email_phone(email, phone)
    if duplicate_errors:
        return jsonify({"error": ", ".join(duplicate_errors)}), 400
    
    try:
        if role == 'customer':
            # Create customer
            new_customer = Customer(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                phone=phone
            )
            db.session.add(new_customer)
            db.session.commit()
            # Log successful registration
            log_auth_event('register', True, email, new_customer.id, 'customer', request.remote_addr)
            log_info(f"New customer registered: {new_customer.id} ({email})")
            return customer_schema.jsonify(new_customer), 201
            
        elif role == 'vendor':
            # Create vendor
            new_vendor = Vendor(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                phone=phone,
                business_name=business_name
            )
            db.session.add(new_vendor)
            db.session.commit()
            # Log successful registration
            log_auth_event('register', True, email, new_vendor.id, 'vendor', request.remote_addr)
            log_info(f"New vendor registered: {new_vendor.id} ({email})")
            return vendor_schema.jsonify(new_vendor), 201
            
        elif role == 'rider':
            # Create rider
            new_rider = Rider(
                name=username,
                email=email,
                password_hash=generate_password_hash(password),
                phone=phone,
                verification_status='pending_verification'
            )
            db.session.add(new_rider)
            db.session.commit()
            # Log successful registration
            log_auth_event('register', True, email, new_rider.id, 'rider', request.remote_addr)
            log_info(f"New rider registered: {new_rider.id} ({email})")
            return rider_schema.jsonify(new_rider), 201
            
        else:
            return jsonify({"error": "Invalid role. Must be 'customer', 'vendor', or 'rider'"}), 400
            
    except Exception as e:
        db.session.rollback()
        # Log failed registration attempt
        log_auth_event('register', False, email if 'email' in locals() else None, None, None, request.remote_addr, error=str(e))
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "Invalid request. Please check your input.")

@app.route('/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")
@csrf.exempt  # Public endpoint - authentication handled via JWT tokens
def login():
    try:
        # Validate input data
        data = request.get_json() or {}
        validated_data, errors = validate_request_data(LoginSchema, data)
        
        if errors:
            return jsonify({"error": "Validation failed", "details": errors}), 400
        
        identifier = validated_data['identifier']
        password = validated_data['password']
            
        # 1. Check Admin table (username based)
        admin = Admin.query.filter_by(username=identifier).first()
        if admin and check_password_hash(admin.password_hash, password):
            token = generate_token(
                user_id=admin.id,
                role="admin",
                username=admin.username
            )
            # Log successful authentication
            log_auth_event('login', True, identifier, admin.id, 'admin', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "admin",
                "user_id": admin.id,
                "username": admin.username,
                "redirect_url": "admin/home.html"
            }), 200
            
        # 2. Check Customer table (email or phone)
        customer = Customer.query.filter((Customer.email == identifier) | (Customer.phone == identifier)).first()
        if customer and check_password_hash(customer.password_hash, password):
            token = generate_token(
                user_id=customer.id,
                role="customer",
                username=customer.username,
                email=customer.email,
                phone=customer.phone
            )
            # Log successful authentication
            log_auth_event('login', True, identifier, customer.id, 'customer', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "customer",
                "user_id": customer.id,
                "username": customer.username,
                "email": customer.email,
                "phone": customer.phone,
                "redirect_url": "customer/home.html"
            }), 200
            
        # 3. Check Vendor table
        vendor = Vendor.query.filter((Vendor.email == identifier) | (Vendor.phone == identifier)).first()
        if vendor and check_password_hash(vendor.password_hash, password):
            token = generate_token(
                user_id=vendor.id,
                role="vendor",
                username=vendor.username,
                email=vendor.email,
                phone=vendor.phone
            )
            params = {
                'user_id': str(vendor.id),
                'role': 'vendor',
                'username': str(vendor.username),
                'email': str(vendor.email),
                'phone': str(vendor.phone or ''),
                'token': token
            }
            redirect_url = build_subdomain_url(Config.VENDOR_SUBDOMAIN, '/', params)
            # Log successful authentication
            log_auth_event('login', True, identifier, vendor.id, 'vendor', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "vendor",
                "user_id": vendor.id,
                "business_name": vendor.business_name,
                "username": vendor.username,
                "email": vendor.email,
                "phone": vendor.phone,
                "redirect_url": redirect_url
            }), 200
            
        # 4. Check Rider table
        rider = Rider.query.filter((Rider.email == identifier) | (Rider.phone == identifier)).first()
        if rider and check_password_hash(rider.password_hash, password):
            token = generate_token(
                user_id=rider.id,
                role="rider",
                username=rider.name,
                email=rider.email,
                phone=rider.phone
            )
            params = {
                'user_id': str(rider.id),
                'role': 'rider',
                'username': str(rider.name),
                'email': str(rider.email),
                'phone': str(rider.phone or ''),
                'token': token
            }
            redirect_url = build_subdomain_url(Config.RIDER_SUBDOMAIN, '/', params)
            # Log successful authentication
            log_auth_event('login', True, identifier, rider.id, 'rider', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "rider",
                "user_id": rider.id,
                "username": rider.name,
                "email": rider.email,
                "phone": rider.phone,
                "verification_status": rider.verification_status,
                "redirect_url": redirect_url
            }), 200

        # Log failed authentication attempt
        log_auth_event('login', False, identifier, None, None, request.remote_addr, error="Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return handle_exception(e, {"endpoint": "/login", "method": "POST"}, "Login failed. Please try again.")


# --- Rider Management Endpoints ---

@app.route('/rider/update-vehicle', methods=['POST'])
@require_role('rider')
def update_rider_vehicle():
    """Update rider vehicle details independently"""
    try:
        rider_id = request.form.get('rider_id')
        vehicle_type = request.form.get('vehicle_type')
        vehicle_number = request.form.get('vehicle_number')
        service_zone = request.form.get('service_zone')
        
        if not rider_id:
            return jsonify({"error": "Rider ID required"}), 400
            
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
            
        if vehicle_type: rider.vehicle_type = vehicle_type
        if vehicle_number: rider.vehicle_number = vehicle_number
        if service_zone: rider.service_zone = service_zone
        
        db.session.commit()
        return jsonify({"message": "Vehicle details updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/update-presence', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/rider/update-presence', methods=['GET', 'POST', 'OPTIONS'], subdomain='rider')
@require_role('rider')
def rider_update_presence():
    """Rider updates online status and GPS coordinates"""
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
    if request.method == 'GET':
        rider_id = request.args.get('rider_id')
        if not rider_id: return jsonify({"error": "Rider ID required"}), 400
        rider = Rider.query.get(rider_id)
        if not rider: return jsonify({"error": "Rider not found"}), 404
        return jsonify({"is_online": rider.is_online, "latitude": rider.latitude, "longitude": rider.longitude}), 200
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        rider_id = data.get('rider_id')
        is_online = data.get('is_online')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not rider_id:
            return jsonify({"error": "Rider ID required"}), 400
            
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
            
        if is_online is not None:
            rider.is_online = bool(is_online)
            if rider.is_online:
                rider.last_online_at = datetime.utcnow()
                
        if latitude is not None and longitude is not None:
            rider.latitude = float(latitude)
            rider.longitude = float(longitude)
            # Fetch human-readable address on every coordinate update for the rider
            rider.current_address = _perform_mappls_reverse_geocode(latitude, longitude)
            
        db.session.commit()
        return jsonify({"message": "Rider presence updated", "is_online": rider.is_online, "current_address": rider.current_address}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/profile/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin', 'customer')
def get_vendor_profile(vendor_id):
    """Get full profile details for a vendor"""
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        return jsonify({
            "id": vendor.id,
            "username": vendor.username,
            "business_name": vendor.business_name,
            "email": vendor.email,
            "phone": vendor.phone,
            "business_type": vendor.business_type,
            "bio": vendor.bio,
            "address": vendor.address,
            "latitude": vendor.latitude,
            "longitude": vendor.longitude,
            "current_address": vendor.current_address,
            "city": vendor.city,
            "state": vendor.state,
            "pincode": vendor.pincode
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/update-profile', methods=['PUT'])
@require_role('vendor')
def update_vendor_profile_extended():
    """Update vendor business details"""
    try:
        data = request.json
        vendor_id = data.get('vendor_id')
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
            
        if 'business_name' in data: vendor.business_name = data['business_name']
        if 'email' in data: vendor.email = data['email']
        if 'phone' in data: vendor.phone = data['phone']
        if 'business_type' in data: vendor.business_type = data['business_type']
        if 'bio' in data: vendor.bio = data['bio']
        
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/update-location-details', methods=['POST'])
@require_role('vendor')
def update_vendor_location_details():
    """Update precise shop location and coordinates"""
    try:
        data = request.json
        vendor_id = data.get('vendor_id')
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        vendor.address = data.get('address', vendor.address)
        vendor.city = data.get('city', vendor.city)
        vendor.state = data.get('state', vendor.state)
        vendor.pincode = data.get('pincode', vendor.pincode)
        
        if 'latitude' in data and data['latitude'] is not None:
            vendor.latitude = float(data['latitude'])
        if 'longitude' in data and data['longitude'] is not None:
            vendor.longitude = float(data['longitude'])
            
        db.session.commit()
        return jsonify({"message": "Shop location details updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/update-location', methods=['POST'])
@require_role('vendor')
def vendor_update_location():
    """Update vendor GPS coordinates for delivery matching"""
    try:
        data = request.json
        vendor_id = data.get('vendor_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not vendor_id:
            return jsonify({"error": "Vendor ID required"}), 400
            
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
            
        if latitude is not None and longitude is not None:
            vendor.latitude = float(latitude)
            vendor.longitude = float(longitude)
            
        db.session.commit()
        return jsonify({"message": "Vendor location updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/upload-documents', methods=['POST'])
@require_role('rider')
def upload_rider_documents():
    rider_id = request.form.get('rider_id')
    vehicle_type = request.form.get('vehicle_type')
    vehicle_number = request.form.get('vehicle_number')
    service_zone = request.form.get('service_zone')
    
    if not rider_id:
        return jsonify({"error": "Rider ID required"}), 400
        
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
        
    # Update vehicle details
    if vehicle_type: rider.vehicle_type = vehicle_type
    if vehicle_number: rider.vehicle_number = vehicle_number
    if service_zone: rider.service_zone = service_zone
    
    # Handle file uploads (Legacy/Direct storage to Rider model)
    # Note: New flow uses RiderDocument table via /rider/verification/upload
    if 'dl_document' in request.files:
        file = request.files['dl_document']
        if file and file.filename:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/rider/upload-documents',
                subfolder='rider',
                user_id=int(rider_id),
                doc_type='dl',
                scan_virus=False
            )
            if not error:
                # Delete old file if exists
                if rider.dl_document:
                    delete_file(rider.dl_document)
                rider.dl_document = file_info['path']
                rider.dl_filename = file_info['filename']
                rider.dl_mimetype = file_info['mimetype']
            
    if 'aadhar_document' in request.files:
        file = request.files['aadhar_document']
        if file and file.filename:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/rider/upload-documents',
                subfolder='rider',
                user_id=int(rider_id),
                doc_type='aadhar',
                scan_virus=False
            )
            if not error:
                # Delete old file if exists
                if rider.aadhar_document:
                    delete_file(rider.aadhar_document)
                rider.aadhar_document = file_info['path']
                rider.aadhar_filename = file_info['filename']
                rider.aadhar_mimetype = file_info['mimetype']
            
    # Update status if documents are uploaded
    if rider.dl_document and rider.aadhar_document and rider.vehicle_number:
        rider.verification_status = 'verification_submitted'
        
    try:
        db.session.commit()
        return jsonify({"message": "Documents uploaded successfully", "status": rider.verification_status}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/status/<int:rider_id>', methods=['GET'])
@app.route('/rider/status/<int:rider_id>', methods=['GET'], subdomain='rider')
@require_self_or_role('rider_id', 'admin')
def get_rider_status(rider_id):
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
        
    # Calculate real-time stats
    try:
        # 1. Total Assigned
        total_assigned = DeliveryLog.query.filter_by(assigned_rider_id=rider_id).count()
        
        # 2. Pending Pickup
        pending_pickup = DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.status.in_(['assigned', 'reached_vendor']))
        ).count()
        
        # 3. Out for Delivery
        out_for_delivery = DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.status.in_(['picked_up', 'out_for_delivery']))
        ).count()
        
        # 4. Completed Today (UTC)
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        completed_today_query = DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.status == 'delivered'),
            (DeliveryLog.delivered_at >= today_start)
        )
        completed_today = completed_today_query.count()
        earnings_today = sum(d.total_earning or 0 for d in completed_today_query.all())
        
        # 5. Week/Month Earnings
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)
        
        earnings_week = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.status == 'delivered'),
            (DeliveryLog.delivered_at >= week_start)
        ).all())
        
        earnings_month = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.status == 'delivered'),
            (DeliveryLog.delivered_at >= month_start)
        ).all())
        
        # 6. Pending Payout
        pending_payout = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
            (DeliveryLog.assigned_rider_id == rider_id),
            (DeliveryLog.payout_status == 'pending')
        ).all())
        
    except Exception as e:
        total_assigned = pending_pickup = out_for_delivery = completed_today = 0
        earnings_today = earnings_week = earnings_month = pending_payout = 0

    return jsonify({
        "id": rider.id,
        "name": rider.name,
        "is_online": rider.is_online,
        "verification_status": rider.verification_status,
        "stats": {
            "total_assigned": total_assigned,
            "pending_pickup": pending_pickup,
            "out_for_delivery": out_for_delivery,
            "completed_today": completed_today,
            "earnings_today": round(earnings_today, 2),
            "earnings_week": round(earnings_week, 2),
            "earnings_month": round(earnings_month, 2),
            "pending_payout": round(pending_payout, 2)
        }
    }), 200

@app.route('/rider/profile', methods=['GET'])
@app.route('/rider/profile', methods=['GET'], subdomain='rider')
@require_role('rider')
def get_rider_profile():
    """Get current rider's profile information"""
    # This endpoint is called by frontend to check online status
    # For now, we'll use rider_id from query params or localStorage
    rider_id = request.args.get('rider_id') or request.headers.get('X-Rider-ID')
    
    if not rider_id:
        return jsonify({"error": "Rider ID required"}), 400
    
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
    
    return jsonify({
        "id": rider.id,
        "name": rider.name,
        "email": rider.email,
        "phone": rider.phone,
        "is_online": rider.is_online,
        "verification_status": rider.verification_status,
        "vehicle_type": rider.vehicle_type,
        "service_zone": rider.service_zone
    }), 200

@app.route('/riders', methods=['GET'])
@require_role('admin')
def get_riders():
    """Get all riders"""
    try:
        riders = Rider.query.all()
        result = []
        for r in riders:
            result.append({
                "id": r.id,
                "name": r.name or "Unknown",
                "email": r.email or "N/A",
                "phone": r.phone or "N/A",
                "vehicle_type": r.vehicle_type or "N/A",
                "vehicle_number": r.vehicle_number or "N/A",
                "service_zone": r.service_zone or "N/A",
                "verification_status": r.verification_status or "not-submitted",
                "is_online": r.is_online or False,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "current_address": r.current_address or "Not available",
                "total_deliveries": r.total_deliveries or 0,
                "successful_deliveries": r.successful_deliveries or 0,
                "average_rating": r.average_rating or 0.0,
                "total_earnings": r.total_earnings or 0.0,
                "created_at": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A"
            })
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/approve/<int:rider_id>', methods=['POST'])
@require_role('admin')
def activate_rider(rider_id):
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
        
    rider.verification_status = 'active'
    
    try:
        db.session.commit()
        return jsonify({"message": "Rider approved successfully", "status": rider.verification_status}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# Get all customers
@app.route('/customers', methods=['GET'])
@require_role('admin')
def get_customers():
    try:
        all_customers = Customer.query.all()
        return customers_schema.jsonify(all_customers), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# Get all vendors
@app.route('/vendors', methods=['GET'])
@require_role('admin')
def get_vendors():
    try:
        all_vendors = Vendor.query.all()
        return vendors_schema.jsonify(all_vendors), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# Get approved vendors for order assignment
@app.route('/admin/approved-vendors', methods=['GET'])
@require_role('admin')
def get_approved_vendors():
    """Get only approved/active vendors for admin to assign orders"""
    try:
        approved_vendors = Vendor.query.filter(
            Vendor.verification_status.in_(['approved', 'active'])
        ).all()
        
        result = []
        for v in approved_vendors:
            result.append({
                "id": v.id,
                "username": v.username,
                "business_name": v.business_name or v.username,
                "email": v.email,
                "phone": v.phone,
                "verification_status": v.verification_status
            })
        
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# --- Category Endpoints ---

@app.route('/categories', methods=['POST'])
@require_role('admin')
def create_category():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        name = data.get('name')
        description = data.get('description')
        
        if not name:
            return jsonify({"error": "Name required"}), 400
            
        new_category = Category(name=name, description=description)
        
        db.session.add(new_category)
        db.session.commit()
        return category_schema.jsonify(new_category), 201
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/categories', methods=['GET'])
@require_auth
def get_categories():
    try:
        all_categories = Category.query.all()
        return categories_schema.jsonify(all_categories), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# --- Thread Endpoints ---

@app.route('/threads', methods=['POST'])
@require_auth
def create_thread():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        title = data.get('title')
        content = data.get('content')
        user_id = data.get('user_id')
        category_id = data.get('category_id')
        
        if not title or not content or not user_id:
            return jsonify({"error": "Title, content, and user_id required"}), 400
            
        new_thread = Thread(title=title, content=content, user_id=user_id, category_id=category_id)
        
        db.session.add(new_thread)
        db.session.commit()
        return thread_schema.jsonify(new_thread), 201
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/threads', methods=['GET'])
@require_auth
def get_threads():
    try:
        all_threads = Thread.query.order_by(Thread.created_at.desc()).all()
        return threads_schema.jsonify(all_threads), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/threads/<int:id>', methods=['GET'])
@require_auth
def get_thread(id):
    try:
        thread = Thread.query.get(id)
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        return thread_schema.jsonify(thread), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# --- Comment Endpoints ---

@app.route('/threads/<int:thread_id>/comments', methods=['POST'])
@require_auth
def add_comment(thread_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        content = data.get('content')
        user_id = data.get('user_id')
        parent_comment_id = data.get('parent_comment_id')
        
        if not content or not user_id:
            return jsonify({"error": "Content and user_id required"}), 400
            
        # Verify thread exists
        thread = Thread.query.get(thread_id)
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        
        new_comment = Comment(content=content, user_id=user_id, thread_id=thread_id, parent_comment_id=parent_comment_id)
        
        db.session.add(new_comment)
        db.session.commit()
        return comment_schema.jsonify(new_comment), 201
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/threads/<int:thread_id>/comments', methods=['GET'])
@require_auth
def get_comments(thread_id):
    try:
        comments = Comment.query.filter_by(thread_id=thread_id).order_by(Comment.created_at.asc()).all()
        return comments_schema.jsonify(comments), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# Update user profile endpoint
@app.route('/update-profile', methods=['PUT'])
@require_auth
def update_profile():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        user_id = data.get('user_id')
        role = data.get('role')
        username = data.get('username')
        email = data.get('email')
        phone = data.get('phone')
        
        if not all([user_id, role, username, email, phone]):
            return jsonify({"error": "All fields are required"}), 400
        if role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        else:
            return jsonify({"error": "Invalid role"}), 400
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Check if email already exists for another user
        if role == 'customer':
            existing = Customer.query.filter(Customer.email == email, Customer.id != user_id).first()
        else:
            existing = Vendor.query.filter(Vendor.email == email, Vendor.id != user_id).first()
        
        if existing:
            return jsonify({"error": "Email already in use"}), 400
        
        # Check if phone already exists for another user
        if role == 'customer':
            existing = Customer.query.filter(Customer.phone == phone, Customer.id != user_id).first()
        else:
            existing = Vendor.query.filter(Vendor.phone == phone, Vendor.id != user_id).first()
        
        if existing:
            return jsonify({"error": "Phone number already in use"}), 400
        
        # Update user data
        user.username = username
        user.email = email
        user.phone = phone
        
        db.session.commit()
        
        return jsonify({
            "message": "Profile updated successfully",
            "username": user.username,
            "email": user.email,
            "phone": user.phone
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# Change password endpoint
@app.route('/change-password', methods=['PUT'])
@require_auth
def change_password():
    data = request.json
    user_id = data.get('user_id')
    role = data.get('role')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not all([user_id, role, current_password, new_password]):
        return jsonify({"error": "All fields are required"}), 400
    
    try:
        if role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        else:
            return jsonify({"error": "Invalid role"}), 400
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# --- Address Management Endpoints ---

@app.route('/addresses/<int:customer_id>', methods=['GET'])
@require_self_or_role('customer_id', 'admin')
def get_customer_addresses(customer_id):
    """Get all addresses for a customer"""
    try:
        addresses = Address.query.filter_by(customer_id=customer_id).all()
        return addresses_schema.jsonify(addresses), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/addresses', methods=['POST'])
@require_role('customer')
def create_address():
    """Create a new address for a customer"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        customer_id = data.get('customer_id')
        address_type = data.get('address_type')  # 'home', 'work', 'other'
        address_line1 = data.get('address_line1')
        address_line2 = data.get('address_line2')
        city = data.get('city')
        state = data.get('state')
        pincode = data.get('pincode')
        landmark = data.get('landmark')
        
        if not all([customer_id, address_type, address_line1, city, state, pincode]):
            return jsonify({"error": "Required fields: customer_id, address_type, address_line1, city, state, pincode"}), 400
        # Check if customer exists
        customer = Customer.query.get(customer_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        # Check if address type already exists for this customer
        existing_address = Address.query.filter_by(customer_id=customer_id, address_type=address_type).first()
        if existing_address:
            return jsonify({"error": f"Address type '{address_type}' already exists. Use update endpoint instead."}), 400
        
        new_address = Address(
            customer_id=customer_id,
            address_type=address_type,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            pincode=pincode,
            landmark=landmark,
            country=data.get('country'),
            alternative_phone=data.get('alternative_phone')
        )
        
        db.session.add(new_address)
        db.session.commit()
        
        return address_schema.jsonify(new_address), 201
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/addresses/<int:address_id>', methods=['PUT'])
@require_auth
def update_address(address_id):
    """Update an existing address"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400
    try:
        address = Address.query.get(address_id)
        if not address:
            return jsonify({"error": "Address not found"}), 404

        # Update fields if provided
        if 'address_line1' in data:
            address.address_line1 = data['address_line1']
        if 'address_line2' in data:
            address.address_line2 = data['address_line2']
        if 'city' in data:
            address.city = data['city']
        if 'state' in data:
            address.state = data['state']
        if 'pincode' in data:
            address.pincode = data['pincode']
        if 'landmark' in data:
            address.landmark = data['landmark']
        if 'country' in data:
            address.country = data['country']
        if 'alternative_phone' in data:
            address.alternative_phone = data['alternative_phone']

        db.session.commit()
        return address_schema.jsonify(address), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/addresses/type/<int:customer_id>/<string:address_type>', methods=['GET'])
@require_self_or_role('customer_id', 'admin')
def get_address_by_type(customer_id, address_type):
    """Get a specific address by type for a customer"""
    try:
        address = Address.query.filter_by(customer_id=customer_id, address_type=address_type).first()
        if not address:
            # Return 200 with None to avoid console errors on frontend
            return jsonify(None), 200
        
        return address_schema.jsonify(address), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# --- Order Management Endpoints ---

@app.route('/orders', methods=['POST'])
@require_role('customer')
def create_order():
    # Validate input data
    data = request.get_json() or {}
    validated_data, errors = validate_request_data(OrderSchema, data)
    
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400
    
    # Extract validated fields
    customer_id = validated_data['customer_id']
    product_type = validated_data['product_type']
    category = validated_data['category']
    neck_type = validated_data.get('neck_type')
    color = validated_data.get('color')
    fabric = validated_data.get('fabric')
    print_type = validated_data.get('print_type')
    quantity = validated_data['quantity']
    delivery_date = validated_data.get('delivery_date')
    price_per_piece_offered = validated_data['price_per_piece']
    
    # Address fields
    address_line1 = validated_data['address_line1']
    address_line2 = validated_data.get('address_line2')
    city = validated_data['city']
    state = validated_data['state']
    pincode = validated_data['pincode']
    country = validated_data.get('country', 'India')
    
    # Payment details
    transaction_id = validated_data.get('transaction_id')
    sample_cost = validated_data.get('sample_cost', 0.0)
        
    try:
        # Determine initial status
        initial_status = 'awaiting_sample_payment'
        if transaction_id:
            initial_status = 'sample_payment_received'

        new_order = Order(
            customer_id=customer_id,
            product_type=product_type,
            category=category,
            neck_type=neck_type,
            color=color,
            fabric=fabric,
            print_type=print_type,
            quantity=quantity,
            price_per_piece_offered=price_per_piece_offered,
            delivery_date=delivery_date,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            pincode=pincode,
            country=country,
            status=initial_status,
            sample_cost=sample_cost
        )
        
        db.session.add(new_order)
        db.session.flush() # Flush to get new_order.id

        # Record Payment if transaction_id exists
        if transaction_id:
            try:
                # Get payment details from request if available
                payment_method = data.get('payment_method', 'card')
                payment_details_str = data.get('payment_details', '')
                
                new_payment = Payment(
                    transaction_id=transaction_id,
                    order_id=new_order.id,
                    customer_id=customer_id,
                    payment_type='sample',
                    payment_method=payment_method,
                    amount=float(sample_cost) if sample_cost else 0.0,
                    currency='INR',
                    status='success',
                    payment_details=payment_details_str,
                    processed_at=datetime.utcnow()
                )
                db.session.add(new_payment)
            except Exception:
                # Don't fail the order creation if payment record fails
                pass

        db.session.commit()
        
        return order_schema.jsonify(new_order), 201
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders', methods=['GET'])
@require_role('admin')
def get_all_orders():
    """Get all orders (for admin)"""
    try:
        orders = Order.query.order_by(Order.created_at.desc()).all()
        return orders_schema.jsonify(orders), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/customer/<int:customer_id>', methods=['GET'])
@require_self_or_role('customer_id', 'admin', 'vendor')
def get_customer_orders(customer_id):
    """Get orders for a specific customer"""
    try:
        orders = Order.query.filter_by(customer_id=customer_id).order_by(Order.created_at.desc()).all()
        return orders_schema.jsonify(orders), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    """Get a single order by ID"""
    try:
        order = Order.query.get_or_404(order_id)
        return order_schema.jsonify(order), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# ==========================================
# PAYMENT HISTORY ENDPOINTS
# ==========================================

@app.route('/api/admin/payments', methods=['GET'])
@require_role('admin')
def get_all_payments():
    """Get all payment transactions for admin payment history"""
    try:
        payments = Payment.query.order_by(Payment.created_at.desc()).all()
        
        result = []
        for p in payments:
            # Get customer info
            customer = Customer.query.get(p.customer_id)
            customer_name = customer.username if customer else "Unknown"
            customer_email = customer.email if customer else "N/A"
            
            # Get order info
            order = Order.query.get(p.order_id)
            order_product = order.product_type if order else "N/A"
            
            result.append({
                'id': p.id,
                'transaction_id': p.transaction_id,
                'order_id': p.order_id,
                'customer_id': p.customer_id,
                'customer_name': customer_name,
                'customer_email': customer_email,
                'order_product': order_product,
                'payment_type': p.payment_type,
                'payment_method': p.payment_method,
                'amount': p.amount,
                'currency': p.currency,
                'status': p.status,
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'processed_at': p.processed_at.isoformat() if p.processed_at else None,
                'payment_details': p.payment_details
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/payments/<int:payment_id>', methods=['GET'])
@require_auth
def get_payment(payment_id):
    """Get a single payment by ID"""
    try:
        payment = Payment.query.get_or_404(payment_id)
        
        # Get related entities
        customer = Customer.query.get(payment.customer_id)
        order = Order.query.get(payment.order_id)
        
        return jsonify({
            'id': payment.id,
            'transaction_id': payment.transaction_id,
            'order_id': payment.order_id,
            'customer': {
                'id': customer.id if customer else None,
                'name': customer.username if customer else "Unknown",
                'email': customer.email if customer else "N/A"
            },
            'order': {
                'id': order.id if order else None,
                'product_type': order.product_type if order else "N/A",
                'quantity': order.quantity if order else 0
            },
            'payment_type': payment.payment_type,
            'payment_method': payment.payment_method,
            'amount': payment.amount,
            'currency': payment.currency,
            'status': payment.status,
            'payment_details': payment.payment_details,
            'created_at': payment.created_at.isoformat() if payment.created_at else None,
            'processed_at': payment.processed_at.isoformat() if payment.processed_at else None,
            'notes': payment.notes
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")




# --- Vendor Quotation Management ---

@app.route('/vendor-quotations', methods=['POST'])
@require_role('admin')
def create_vendor_quotation():
    """Create a new vendor quotation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # Validate required fields
        required_fields = ['vendor_id', 'product_type', 'category', 'base_cost_per_piece', 'admin_profit_margin_per_piece']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        new_quotation = VendorQuotation(
            vendor_id=data['vendor_id'],
            product_id=data.get('product_id'),  # Use product_id if provided
            base_cost=data['base_cost_per_piece'],
            status='pending'
        )
        
        db.session.add(new_quotation)
        db.session.commit()
        
        return vendor_quotation_schema.jsonify(new_quotation), 201
    except KeyError as e:
        db.session.rollback()
        return jsonify({"error": "Missing required fields. Please check your input."}), 400
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor-quotations/match/<int:order_id>', methods=['GET'])
@require_auth
def match_vendor_quotations(order_id):
    """Find matching vendor quotations for an order"""
    try:
        order = Order.query.get_or_404(order_id)
        
        # Find exact matches
        quotations = VendorQuotation.query.filter_by(
            product_type=order.product_type,
            category=order.category,
            neck_type=order.neck_type,
            fabric_type=order.fabric,
            print_type=order.print_type
        ).all()
        
        # Filter by customer's offered price
        matching_quotations = []
        for q in quotations:
            if order.price_per_piece_offered >= q.final_price_per_piece:
                matching_quotations.append({
                    'quotation_id': q.id,
                    'vendor_id': q.vendor_id,
                    'vendor_name': q.vendor.business_name or q.vendor.username,
                    'base_cost_per_piece': q.base_cost_per_piece,
                    'admin_profit_margin_per_piece': q.admin_profit_margin_per_piece,
                    'final_price_per_piece': q.final_price_per_piece,
                    'total_price': q.final_price_per_piece * order.quantity,
                    'customer_offered': order.price_per_piece_offered,
                    'profit_margin': order.price_per_piece_offered - q.final_price_per_piece
                })
        
        return jsonify({
            'order_id': order_id,
            'matching_quotations': matching_quotations,
            'count': len(matching_quotations)
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/api/estimate-price', methods=['POST'])
@require_auth
def estimate_price():
    """
    Estimate price for a product configuration.
    Looks up the average price from the ProductCatalog (pre-calculated from all vendor quotations).
    """
    try:
        data = request.json
        product_type = data.get('product_type')
        category = data.get('category')
        neck_type = data.get('neck_type')
        fabric = data.get('fabric')
        size = data.get('size')
        
        if not product_type or not category:
            return jsonify({"error": "Product type and category are required"}), 400
        
        # Build query with available parameters
        query = ProductCatalog.query.filter_by(
            product_type=product_type,
            category=category
        )
        
        if neck_type:
            query = query.filter_by(neck_type=neck_type)
        if fabric:
            query = query.filter_by(fabric=fabric)
        if size:
            query = query.filter_by(size=size)
        
        product = query.first()
        
        if product and product.vendor_count > 0:
            return jsonify({
                "estimated_price": product.final_price,
                "vendor_count": product.vendor_count,
                "found": True
            }), 200
        else:
            # No exact match logic
            # 1. Try to find match with same Product, Category AND Size (ignoring fabric/neck/print)
            # This is important because Size affects price significantly more than fabric often
            query_size = ProductCatalog.query.filter_by(
                product_type=product_type,
                category=category
            ).filter(ProductCatalog.vendor_count > 0)
            
            if size:
                query_size = query_size.filter_by(size=size)
            
            similar_by_size = query_size.all()
            
            if similar_by_size:
                avg = sum(p.final_price for p in similar_by_size) / len(similar_by_size)
                return jsonify({
                    "estimated_price": round(avg, 2),
                    "vendor_count": len(similar_by_size),
                    "found": False,
                    "message": f"Estimate based on size {size}"
                }), 200
                
            # 2. Fallback: Average of all items in this category
            similar = ProductCatalog.query.filter_by(
                product_type=product_type,
                category=category
            ).filter(ProductCatalog.vendor_count > 0).all()
            
            if similar:
                avg = sum(p.final_price for p in similar) / len(similar)
                return jsonify({
                    "estimated_price": round(avg, 2),
                    "vendor_count": len(similar),
                    "found": False,
                    "message": "Estimate based on category average"
                }), 200
            
            return jsonify({
                "estimated_price": 0,
                "vendor_count": 0,
                "found": False,
                "message": "No quotations found for this configuration"
            }), 200
            
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/assign-vendor', methods=['POST'])
@require_role('admin')
def assign_vendor_to_order(order_id):
    """Admin assigns vendor and sends quotation to customer"""
    data = request.json
    
    try:
        order = Order.query.get_or_404(order_id)
        
        order.selected_vendor_id = data['vendor_id']
        order.quotation_price_per_piece = data['quotation_price_per_piece']
        order.quotation_total_price = data['quotation_price_per_piece'] * order.quantity
        order.sample_cost = data.get('sample_cost', 500.0)  # Default sample cost
        order.status = 'quotation_sent_to_customer'
        
        db.session.commit()
        
        return order_schema.jsonify(order), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/quotation-response', methods=['POST'])
@require_role('customer')
def customer_quotation_response(order_id):
    """Customer accepts or rejects quotation"""
    data = request.json
    action = data.get('action')  # 'accept' or 'reject'
    
    try:
        order = Order.query.get_or_404(order_id)
        
        if action == 'reject':
            order.status = 'quotation_rejected_by_customer'
            db.session.commit()
            return jsonify({"message": "Quotation rejected"}), 200
            
        elif action == 'accept':
            # Create payment record for sample
            sample_payment = CustomerPayment(
                order_id=order_id,
                payer_type='customer',
                payer_id=order.customer_id,
                receiver_type='admin',
                receiver_id=1,  # Admin ID
                amount=order.sample_cost,
                payment_type='sample_payment',
                status='completed'
            )
            
            db.session.add(sample_payment)
            order.status = 'sample_requested'
            db.session.commit()
            
            return jsonify({"message": "Sample payment successful, sample requested"}), 200
        else:
            return jsonify({"error": "Invalid action"}), 400
            
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/sample-response', methods=['POST'])
@require_role('customer')
def customer_sample_response(order_id):
    """Customer approves or rejects sample"""
    data = request.json
    action = data.get('action')  # 'approve' or 'reject'
    
    try:
        order = Order.query.get_or_404(order_id)
        
        if action == 'reject':
            order.status = 'sample_rejected'
            db.session.commit()
            return jsonify({"message": "Sample rejected"}), 200
            
        elif action == 'approve':
            order.status = 'awaiting_advance_payment'
            db.session.commit()
            return jsonify({
                "message": "Sample approved, awaiting 50% advance payment",
                "advance_amount": order.quotation_total_price * 0.50
            }), 200
        else:
            return jsonify({"error": "Invalid action"}), 400
            
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/advance-payment', methods=['POST'])
@require_role('customer')
def process_advance_payment(order_id):
    """Process 50% advance payment from customer"""
    try:
        order = Order.query.get_or_404(order_id)
        
        advance_amount = order.quotation_total_price * 0.50
        vendor_initial_payout = order.quotation_total_price * 0.25
        
        # Record customer's 50% advance payment to admin
        advance_payment = CustomerPayment(
            order_id=order_id,
            payer_type='customer',
            payer_id=order.customer_id,
            receiver_type='admin',
            receiver_id=1,
            amount=advance_amount,
            payment_type='advance_50',
            status='completed'
        )
        
        # Record admin's 25% payout to vendor
        vendor_payment = CustomerPayment(
            order_id=order_id,
            payer_type='admin',
            payer_id=1,
            receiver_type='vendor',
            receiver_id=order.selected_vendor_id,
            amount=vendor_initial_payout,
            payment_type='vendor_initial_payout',
            status='completed'
        )
        
        order.vendor_initial_payout = vendor_initial_payout
        order.status = 'in_production'
        
        db.session.add(advance_payment)
        db.session.add(vendor_payment)
        db.session.commit()
        
        return jsonify({
            "message": "Advance payment processed successfully",
            "customer_paid": advance_amount,
            "vendor_received": vendor_initial_payout,
            "admin_holds": advance_amount - vendor_initial_payout
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/update-status', methods=['POST'])
@require_role('admin', 'vendor')
def update_order_status(order_id):
    """Update order status (for vendor/admin)"""
    data = request.json
    
    try:
        order = Order.query.get_or_404(order_id)
        order.status = data['status']
        db.session.commit()
        
        return order_schema.jsonify(order), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/feedback', methods=['POST'])
@require_role('customer')
def submit_order_feedback(order_id):
    """Customer submits feedback after delivery"""
    data = request.json
    
    try:
        order = Order.query.get_or_404(order_id)
        
        order.rating = data.get('rating')
        order.delivery_on_time = data.get('delivery_on_time', True)
        order.delivery_delay_days = data.get('delivery_delay_days', 0)
        order.defect_reported = data.get('defect_reported', False)
        order.feedback_comment = data.get('feedback_comment', '')
        
        # Calculate penalties
        total_price = order.quotation_total_price
        penalty = 0.0
        
        # Late delivery penalty
        if order.delivery_delay_days > 0:
            if order.delivery_delay_days <= 3:
                penalty += total_price * 0.05
            elif order.delivery_delay_days <= 7:
                penalty += total_price * 0.10
            else:
                penalty += total_price * 0.20
        
        # Rating penalty
        if order.rating == 3:
            penalty += total_price * 0.05
        elif order.rating == 2:
            penalty += total_price * 0.10
        elif order.rating == 1:
            penalty += total_price * 0.20
        
        # Defect penalty
        if order.defect_reported:
            penalty += total_price * 0.15
        
        # Calculate final vendor payout
        vendor_remaining_base = total_price * 0.25
        vendor_final_payout = max(0, vendor_remaining_base - penalty)
        
        order.penalty_amount_total = penalty
        order.vendor_final_payout = vendor_final_payout
        order.status = 'completed_with_penalty' if penalty > 0 else 'completed'
        
        # Create final vendor payment record
        final_payment = CustomerPayment(
            order_id=order_id,
            payer_type='admin',
            payer_id=1,
            receiver_type='vendor',
            receiver_id=order.selected_vendor_id,
            amount=vendor_final_payout,
            payment_type='vendor_final_payout',
            status='completed'
        )
        
        db.session.add(final_payment)
        db.session.commit()
        
        return jsonify({
            "message": "Feedback submitted successfully",
            "penalty_applied": penalty,
            "vendor_final_payout": vendor_final_payout,
            "order_status": order.status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/orders/<int:order_id>/payments', methods=['GET'])
@require_auth
def get_order_payments(order_id):
    """Get all payments for an order"""
    try:
        # Get both admin payments (transaction payments) and customer payments (internal tracking)
        admin_payments = Payment.query.filter_by(order_id=order_id).all()
        customer_payments = CustomerPayment.query.filter_by(order_id=order_id).all()
        
        # Combine and format payments
        result = []
        for p in admin_payments:
            result.append({
                'id': p.id,
                'type': 'transaction',
                'transaction_id': p.transaction_id,
                'payment_type': p.payment_type,
                'payment_method': p.payment_method,
                'amount': p.amount,
                'currency': p.currency,
                'status': p.status,
                'created_at': p.created_at.isoformat() if p.created_at else None
            })
        for p in customer_payments:
            result.append({
                'id': p.id,
                'type': 'internal',
                'payer_type': p.payer_type,
                'payer_id': p.payer_id,
                'receiver_type': p.receiver_type,
                'receiver_id': p.receiver_id,
                'payment_type': p.payment_type,
                'amount': p.amount,
                'status': p.status,
                'timestamp': p.timestamp.isoformat() if p.timestamp else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# Vendor Verification Routes
from datetime import datetime

@app.route('/vendor/verification/upload', methods=['POST'])
@require_role('vendor')
def upload_vendor_document():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    vendor_id = request.form.get('vendor_id')
    doc_type = request.form.get('doc_type')
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not file or not vendor_id or not doc_type:
        return jsonify({"error": "Missing data"}), 400
    
    # Verify vendor exists
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
    
    try:
        # Validate and save file using secure upload utility
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/vendor/verification/upload',
            subfolder='vendor',
            user_id=int(vendor_id),
            doc_type=doc_type,
            scan_virus=False  # Set to True if ClamAV is configured
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Check if row exists for vendor
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if not doc_row:
            doc_row = VendorDocument(vendor_id=vendor_id)
            db.session.add(doc_row)
        
        # Store file path instead of file data
        if hasattr(doc_row, doc_type):
            # Delete old file if exists
            old_path = getattr(doc_row, doc_type, None)
            if old_path:
                delete_file(old_path)
            
            # Store relative path to file
            setattr(doc_row, doc_type, file_info['path'])
            
            # Update metadata
            meta = {
                'filename': file_info['filename'],
                'original_filename': file_info['original_filename'],
                'mimetype': file_info['mimetype'],
                'size': file_info['size'],
                'status': 'uploaded',
                'uploaded_at': datetime.utcnow().isoformat()
            }
            setattr(doc_row, f"{doc_type}_meta", meta)
            
            # Save manual fields if provided during upload
            if doc_type == 'pan' and request.form.get('pan_number'):
                doc_row.pan_number = request.form.get('pan_number')
            if doc_type == 'aadhar' and request.form.get('aadhar_number'):
                doc_row.aadhar_number = request.form.get('aadhar_number')
            if doc_type == 'gst' and request.form.get('gst_number'):
                doc_row.gst_number = request.form.get('gst_number')
            if doc_type == 'bank':
                if request.form.get('bank_account_number'): doc_row.bank_account_number = request.form.get('bank_account_number')
                if request.form.get('bank_holder_name'): doc_row.bank_holder_name = request.form.get('bank_holder_name')
                if request.form.get('bank_branch'): doc_row.bank_branch = request.form.get('bank_branch')
                if request.form.get('ifsc_code'): doc_row.ifsc_code = request.form.get('ifsc_code')
            
            doc_row.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                "message": "File uploaded successfully",
                "fileName": file.filename,
                "fileSize": file_size
            }), 200
        else:
            return jsonify({"error": "Invalid document type"}), 400
            
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/verification/submit', methods=['POST'])
@require_role('vendor')
def submit_verification():
    data = request.json
    vendor_id = data.get('vendor_id')
    if vendor_id:
        vendor_id = int(vendor_id)

    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
        
    # Update manual fields in VendorDocument
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    if not doc_row:
        # Should exist if docs were uploaded, but create if not
        doc_row = VendorDocument(vendor_id=vendor_id)
        db.session.add(doc_row)
    
    if data.get('pan_number'): doc_row.pan_number = data.get('pan_number')
    if data.get('aadhar_number'): doc_row.aadhar_number = data.get('aadhar_number')
    if data.get('gst_number'): doc_row.gst_number = data.get('gst_number')
    if data.get('bank_account_number'): doc_row.bank_account_number = data.get('bank_account_number')
    if data.get('bank_holder_name'): doc_row.bank_holder_name = data.get('bank_holder_name')
    if data.get('bank_branch'): doc_row.bank_branch = data.get('bank_branch')
    if data.get('ifsc_code'): doc_row.ifsc_code = data.get('ifsc_code')
        
    vendor.verification_status = 'pending'
    db.session.commit()
    
    return jsonify({"message": "Verification submitted successfully"}), 200

@app.route('/vendor/verification/status/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_verification_status(vendor_id):
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
    
    # Fetch documents row for this vendor
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    
    # Build documents dict (excluding quotation - submitted post-approval)
    documents = {}
    if doc_row:
        for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
            if hasattr(doc_row, f"{doc_type}_meta"):
                meta = getattr(doc_row, f"{doc_type}_meta")
                doc_data = {
                    'status': 'pending', 
                    'fileName': '', 
                    'uploadedDate': '',
                    'adminRemarks': ''
                }
                
                if meta:
                    doc_data = {
                        'status': meta.get('status', 'pending'),
                        'fileName': meta.get('filename'),
                        'fileSize': meta.get('size'),
                        'uploadedDate': meta.get('uploaded_at'),
                        'adminRemarks': meta.get('remarks')
                    }
                
                # Add manual fields
                if doc_type == 'pan': doc_data['pan_number'] = doc_row.pan_number
                if doc_type == 'aadhar': doc_data['aadhar_number'] = doc_row.aadhar_number
                if doc_type == 'gst': doc_data['gst_number'] = doc_row.gst_number
                if doc_type == 'bank':
                    doc_data['bank_account_number'] = doc_row.bank_account_number
                    doc_data['bank_holder_name'] = doc_row.bank_holder_name
                    doc_data['bank_branch'] = doc_row.bank_branch
                    doc_data['ifsc_code'] = doc_row.ifsc_code
                    
                documents[doc_type] = doc_data
        
    return jsonify({
        "status": vendor.verification_status,
        "documents": documents,
        "admin_remarks": vendor.admin_remarks
    }), 200

@app.route('/vendor/verification/document/<int:vendor_id>/<doc_type>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_document(vendor_id, doc_type):
    """Retrieve a specific document for viewing/downloading"""
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    
    if not doc_row or not hasattr(doc_row, doc_type):
        return jsonify({"error": "Document not found"}), 404
        
    file_path = getattr(doc_row, doc_type)
    meta = getattr(doc_row, f"{doc_type}_meta")
    
    if not file_path or not meta:
        return jsonify({"error": "Document content missing"}), 404
    
    # Get absolute file path
    from file_upload import get_file_path_from_db
    absolute_path = get_file_path_from_db(file_path)
    
    if not absolute_path or not os.path.exists(absolute_path):
        return jsonify({"error": "File not found on disk"}), 404
    
    return send_file(
        absolute_path,
        mimetype=meta.get('mimetype', 'application/octet-stream'),
        as_attachment=False,
        download_name=meta.get('filename', f'{doc_type}.pdf')
    )

@app.route('/api/admin/order-stats', methods=['GET'])
@require_role('admin')
def get_admin_order_stats():
    """Get count of orders by status bucket for Admin Dashboard"""
    try:
        # 1. New Orders
        # Includes: Pending review, quotation sent, and newly paid samples
        new_orders_count = Order.query.filter(
            Order.status.in_([
                'pending_admin_review', 
                'quotation_sent_to_customer', 
                'sample_payment_received'
            ])
        ).count()
        
        # 2. In Production
        # Includes: Assigned to vendor, starting production, in progress
        production_count = Order.query.filter(
            Order.status.in_([
                'sample_requested', 
                'awaiting_advance_payment', 
                'in_production',
                'assigned',
                'vendor_assigned',
                'accepted_by_vendor'
            ])
        ).count()
        
        # 3. Ready for Dispatch
        # Includes: Packed, ready, dispatched, out for delivery
        dispatch_count = Order.query.filter(
            Order.status.in_([
                'awaiting_dispatch', 
                'ready_for_dispatch', 
                'awaiting_delivery', 
                'reached_vendor', 
                'picked_up', 
                'out_for_delivery',
                'packed_ready',
                'dispatched'
            ])
        ).count()
        
        # 4. Completed
        completed_count = Order.query.filter(
            Order.status.in_([
                'completed', 
                'completed_with_penalty', 
                'delivered'
            ])
        ).count()
        
        return jsonify({
            "newOrders": new_orders_count,
            "inProduction": production_count,
            "readyDispatch": dispatch_count,
            "completed": completed_count
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/api/vendor/<int:vendor_id>/order-stats', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_order_stats(vendor_id):
    """Get count of orders for a specific vendor"""
    try:
        # 1. New Orders (Assigned to this vendor for review/acceptance)
        new_orders_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['assigned'])
        ).count()

        # 2. In Production
        in_production_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['accepted_by_vendor', 'in_production', 'cutting', 'sewing', 'finishing', 'packaging'])
        ).count()

        # 3. Ready for Dispatch
        ready_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['ready_for_dispatch', 'packed_ready', 'ready_for_pickup'])
        ).count()

        # 4. Completed
        completed_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['completed', 'completed_with_penalty', 'delivered', 'picked_up_by_rider', 'out_for_delivery'])
        ).count()
        
        return jsonify({
            "newOrders": new_orders_count,
            "inProduction": in_production_count,
            "readyForDispatch": ready_count,
            "completed": completed_count
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/admin/vendor-requests', methods=['GET'])
@require_role('admin')
def get_vendor_requests():
    # Get only vendors with pending, under-review, or rejected status
    # Exclude approved and active vendors (they should appear in verified vendors list)
    vendors = Vendor.query.filter(
        Vendor.verification_status.in_(['pending', 'under-review'])
    ).all()
    

    
    result = []
    for v in vendors:
        try:
            # Fetch documents for this vendor
            doc_row = VendorDocument.query.filter_by(vendor_id=v.id).first()
            documents = {}
            if doc_row:
                for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                    if hasattr(doc_row, f"{doc_type}_meta"):
                        meta = getattr(doc_row, f"{doc_type}_meta")
                        if meta:
                            doc_data = {
                                'status': meta.get('status', 'pending'),
                                'fileName': meta.get('filename'),
                                'fileSize': meta.get('size'),
                                'uploadedDate': meta.get('uploaded_at')
                            }
                            
                            # Add manual fields
                            if doc_type == 'pan': doc_data['pan_number'] = doc_row.pan_number
                            if doc_type == 'aadhar': doc_data['aadhar_number'] = doc_row.aadhar_number
                            if doc_type == 'gst': doc_data['gst_number'] = doc_row.gst_number
                            if doc_type == 'bank':
                                doc_data['bank_account_number'] = doc_row.bank_account_number
                                doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                doc_data['bank_branch'] = doc_row.bank_branch
                                doc_data['ifsc_code'] = doc_row.ifsc_code
                                
                            documents[doc_type] = doc_data
            
            result.append({
                "id": v.id,
                "name": v.business_name or v.username or "Unknown",
                "businessType": v.business_type or "N/A",
                "submitted": v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                "status": v.verification_status or "pending",
                "documents": documents,
                "contact": {
                    "email": v.email or "N/A", 
                    "phone": v.phone or "N/A"
                },
                "address": v.address or "N/A",
                "adminRemarks": v.admin_remarks or ""
            })
        except Exception:
            pass
    
    return jsonify(result), 200

@app.route('/admin/rejected-vendors', methods=['GET'])
@require_role('admin')
def get_rejected_vendors():
    """Get only rejected vendors"""
    vendors = Vendor.query.filter_by(verification_status='rejected').all()
    
    result = []
    for v in vendors:
        try:
            doc_row = VendorDocument.query.filter_by(vendor_id=v.id).first()
            documents = {}
            if doc_row:
                for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                    if hasattr(doc_row, f"{doc_type}_meta"):
                        meta = getattr(doc_row, f"{doc_type}_meta")
                        if meta:
                            doc_data = {
                                'status': meta.get('status', 'pending'),
                                'fileName': meta.get('filename'),
                                'fileSize': meta.get('size'),
                                'uploadedDate': meta.get('uploaded_at'),
                                'adminRemarks': meta.get('remarks')
                            }
                            documents[doc_type] = doc_data
            
            result.append({
                'id': v.id,
                'name': v.username or 'Unknown',
                'businessName': v.business_name,
                'email': v.email,
                'phone': v.phone,
                'status': v.verification_status,
                'submitted': v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                'adminRemarks': v.admin_remarks,
                'documents': documents
            })
        except Exception as e:
            log_error_with_context(e, {"vendor_id": v.id, "endpoint": "get_rejected_vendors", "action": "processing_vendor_data"})
            continue
            
    return jsonify(result), 200

@app.route('/admin/vendor-requests/<int:vendor_id>/approve', methods=['POST'])
@require_role('admin')
def approve_vendor_request(vendor_id):
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
        
    # Set default values for vendor configuration (will be updated after quotation submission)
    vendor.commission_rate = 15.0
    vendor.payment_cycle = 'monthly'
    vendor.service_zone = 'all'
    
    vendor.verification_status = 'approved'
    
    # Update all document statuses to approved (excluding quotation)
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    if doc_row:
        for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
            meta_attr = f"{doc_type}_meta"
            if hasattr(doc_row, meta_attr):
                meta = getattr(doc_row, meta_attr)
                if meta:
                    meta['status'] = 'approved'
                    setattr(doc_row, meta_attr, meta)
        
    
    # Create notification
    notif = Notification(
        user_id=vendor_id,
        user_type='vendor',
        title='Verification Approved',
        message='Your account verification has been approved. Please submit your quotation to proceed.',
        type='verification'
    )
    db.session.add(notif)
    
    db.session.commit()
    return jsonify({"message": "Vendor approved"}), 200

@app.route('/admin/vendor-requests/<int:vendor_id>/reject', methods=['POST'])
@require_role('admin')
def reject_vendor_request(vendor_id):
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
        
    data = request.json
    global_reason = data.get('reason', 'Documents rejected')
    rejected_docs = data.get('rejected_documents', {}) # Dictionary: { doc_type: reason }
    

    vendor.verification_status = 'rejected'
    vendor.admin_remarks = global_reason
    
    # Update document statuses
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    if doc_row:
        # If we have specific rejected docs, update them
        if rejected_docs:
            for doc_type, reason in rejected_docs.items():
                meta_attr = f"{doc_type}_meta"
                if hasattr(doc_row, meta_attr):
                    # Create a new dict to ensure SQLAlchemy detects the change
                    current_meta = getattr(doc_row, meta_attr)
                    
                    meta = dict(current_meta) if current_meta else {}
                    
                    meta['status'] = 'rejected'
                    meta['remarks'] = reason
                    # Clear uploaded date to force re-upload logic if needed? No, keep it.
                    
                    setattr(doc_row, meta_attr, meta)
                    # Explicitly flag modification just in case (though re-assignment should work)
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(doc_row, meta_attr)
                    
                    # Verify update
            
        else:
             # Fallback to old behavior: Reject ALL
             for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature', 'quotation']:
                meta_attr = f"{doc_type}_meta"
                if hasattr(doc_row, meta_attr):
                    current_meta = getattr(doc_row, meta_attr)
                    meta = dict(current_meta) if current_meta else {}
                    
                    meta['status'] = 'rejected'
                    meta['remarks'] = global_reason
                    setattr(doc_row, meta_attr, meta)
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(doc_row, meta_attr)
        
    db.session.commit()
    return jsonify({"message": "Vendor rejected"}), 200

@app.route('/admin/vendor-requests/<int:vendor_id>/delete', methods=['DELETE'])
@require_role('admin')
def delete_vendor_request(vendor_id):
    """Delete vendor's verification request and all documents to allow re-submission"""
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
    
    # Reset verification status
    vendor.verification_status = 'not-submitted'
    vendor.admin_remarks = None
    
    # Delete all documents
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    if doc_row:
        db.session.delete(doc_row)
    
    db.session.commit()
    return jsonify({"message": "Vendor request deleted successfully"}), 200


# Post-Approval Quotation Submission Endpoints
@app.route('/vendor/quotation/submit', methods=['POST'])
@require_role('vendor')
def submit_vendor_quotation():
    """Vendor submits quotation and commission rate after approval"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    vendor_id = request.form.get('vendor_id')
    commission_rate = request.form.get('commission_rate')
    
    if not file or not vendor_id or not commission_rate:
        return jsonify({"error": "Missing required data"}), 400
        
    if float(commission_rate) < 15:
        return jsonify({"error": "Commission rate must be at least 15%"}), 400
    
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if vendor.verification_status != 'approved':
            return jsonify({"error": "Vendor must be approved first"}), 403
        
        # Validate and save file using secure upload utility
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/vendor/submit-quotation',
            subfolder='vendor',
            user_id=int(vendor_id),
            doc_type='quotation',
            scan_virus=False
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Check if submission already exists
        existing = VendorQuotationSubmission.query.filter_by(vendor_id=vendor_id).first()
        if existing:
            # Delete old file if exists
            if existing.quotation_file:
                delete_file(existing.quotation_file)
            # Update existing submission
            existing.quotation_file = file_info['path']
            existing.quotation_filename = file_info['filename']
            existing.quotation_mimetype = file_info['mimetype']
            existing.proposed_commission_rate = float(commission_rate)
            existing.status = 'pending'
            existing.submitted_at = datetime.utcnow()
            submission = existing
        else:
            # Create new submission
            submission = VendorQuotationSubmission(
                vendor_id=vendor_id,
                quotation_file=file_info['path'],
                quotation_filename=file_info['filename'],
                quotation_mimetype=file_info['mimetype'],
                proposed_commission_rate=float(commission_rate)
            )
            db.session.add(submission)
        
        db.session.commit()
        return jsonify({"message": "Quotation submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/quotation/status/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_quotation_status(vendor_id):
    """Get vendor's quotation submission status"""
    submission = VendorQuotationSubmission.query.filter_by(vendor_id=vendor_id).first()
    
    if not submission:
        return jsonify({
            "submitted": False,
            "status": None
        }), 200
    
    return jsonify({
        "submitted": True,
        "status": submission.status,
        "proposed_commission_rate": submission.proposed_commission_rate,
        "filename": submission.quotation_filename,
        "submitted_at": submission.submitted_at.isoformat() if submission.submitted_at else None,
        "admin_remarks": submission.admin_remarks
    }), 200

@app.route('/vendor/quotation/download/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def download_quotation(vendor_id):
    """Download vendor's quotation file"""
    submission = VendorQuotationSubmission.query.filter_by(vendor_id=vendor_id).first()
    
    if not submission or not submission.quotation_file:
        return jsonify({"error": "Quotation not found"}), 404
    
    # Get absolute file path
    from file_upload import get_file_path_from_db
    absolute_path = get_file_path_from_db(submission.quotation_file)
    
    if not absolute_path or not os.path.exists(absolute_path):
        return jsonify({"error": "File not found on disk"}), 404
    
    return send_file(
        absolute_path,
        mimetype=submission.quotation_mimetype or 'application/pdf',
        as_attachment=True,
        download_name=submission.quotation_filename
    )

@app.route('/admin/quotation-submissions', methods=['GET'])
@require_role('admin')
def get_quotation_submissions():
    """Get all pending quotation submissions for admin"""
    submissions = VendorQuotationSubmission.query.filter_by(status='pending').all()
    
    result = []
    for sub in submissions:
        vendor = Vendor.query.get(sub.vendor_id)
        if vendor:  # Only include if vendor exists
            result.append({
                "id": sub.id,
                "vendor_id": sub.vendor_id,
                "vendor_name": vendor.business_name or vendor.username or "Unknown",
                "proposed_commission_rate": sub.proposed_commission_rate if sub.proposed_commission_rate is not None else 0,
                "filename": sub.quotation_filename or "No file",
                "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
                "status": sub.status or "pending"
            })
    
    return jsonify(result), 200

@app.route('/admin/quotation-submissions/<int:submission_id>/approve', methods=['POST'])
@require_role('admin')
def approve_quotation_submission(submission_id):
    """
    Admin approves quotation and sets final commission rate.
    Parses the quotation file and recalculates average costs in ProductCatalog.
    """
    try:
        data = request.json
        final_commission_rate = data.get('commission_rate')
        
        if not final_commission_rate:
            return jsonify({"error": "Commission rate is required"}), 400
        
        submission = VendorQuotationSubmission.query.get(submission_id)
        if not submission:
            return jsonify({"error": "Submission not found"}), 404
        
        if submission.status == 'approved':
            return jsonify({"error": "This submission is already approved"}), 400
        
        vendor = Vendor.query.get(submission.vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Update submission status first
        submission.status = 'approved'
        submission.reviewed_at = datetime.utcnow()
        submission.admin_remarks = data.get('remarks', 'Approved')
        
        # Update vendor's commission rate
        vendor.commission_rate = float(final_commission_rate)
        
        # Commit the approval first
        db.session.commit()
        
        # Now recalculate all product averages from all approved quotations
        products_updated = recalculate_all_product_averages_from_files()
        
        # Create notification
        notif = Notification(
            user_id=vendor.id,
            user_type='vendor',
            title='Quotation Approved',
            message=f'Your quotation has been approved with a commission rate of {final_commission_rate}%. Product pricing has been updated.',
            type='verification'
        )
        db.session.add(notif)
        db.session.commit()
        
        return jsonify({
            "message": "Quotation approved successfully",
            "products_updated": products_updated
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


def parse_quotation_file_data(file_data, filename, mimetype):
    """
    Parse Excel or CSV quotation file and return list of dictionaries.
    Expected columns: Product Type, Category, Neck Type, Fabric/Fabric Type, Size, Base Cost/Base Cost Per Piece
    """
    try:
        quotations = []
        
        if mimetype and ('spreadsheet' in mimetype or 'excel' in mimetype) or (filename and filename.endswith(('.xlsx', '.xls'))):
            # Parse Excel file
            workbook = openpyxl.load_workbook(io.BytesIO(file_data))
            sheet = workbook.active
            
            # Get headers from first row
            headers = [str(cell.value).strip().lower().replace(' ', '_') if cell.value else '' for cell in sheet[1]]
            
            for row in sheet.iter_rows(min_row=2, values_only=True):
                if not row[0]:  # Skip empty rows
                    continue
                
                quotation = {}
                for i, header in enumerate(headers):
                    if header and i < len(row):
                        value = row[i]
                        # Normalize header names
                        if header in ['base_cost_per_piece', 'base_cost', 'price', 'cost']:
                            quotation['base_cost'] = value
                        elif header in ['product_type', 'product']:
                            quotation['product_type'] = value
                        elif header in ['fabric_type', 'fabric']:
                            quotation['fabric'] = value
                        else:
                            quotation[header] = value
                
                if quotation.get('product_type') and quotation.get('base_cost'):
                    quotations.append(quotation)
        
        elif mimetype and 'csv' in mimetype or (filename and filename.endswith('.csv')):
            # Parse CSV file
            csv_data = file_data.decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_data))
            
            for row in reader:
                quotation = {}
                for key, value in row.items():
                    normalized_key = key.strip().lower().replace(' ', '_')
                    # Normalize header names
                    if normalized_key in ['base_cost_per_piece', 'base_cost', 'price', 'cost']:
                        quotation['base_cost'] = value
                    elif normalized_key in ['product_type', 'product']:
                        quotation['product_type'] = value
                    elif normalized_key in ['fabric_type', 'fabric']:
                        quotation['fabric'] = value
                    else:
                        quotation[normalized_key] = value
                
                if quotation.get('product_type') and quotation.get('base_cost'):
                    quotations.append(quotation)
        
        return quotations
    except Exception as e:
        return None


def find_or_create_product_catalog(product_type, category, neck_type, fabric, size):
    """
    Find existing product in catalog or create new one if it doesn't exist.
    Returns the ProductCatalog object.
    """
    if not product_type or not category:
        return None
    
    # Normalize values
    product_type = str(product_type).strip()
    category = str(category).strip()
    neck_type = str(neck_type).strip() if neck_type else 'Standard'
    fabric = str(fabric).strip() if fabric else 'Cotton'
    size = str(size).strip() if size else 'M'
    
    product = ProductCatalog.query.filter_by(
        product_type=product_type,
        category=category,
        neck_type=neck_type,
        fabric=fabric,
        size=size
    ).first()
    
    if not product:
        product = ProductCatalog(
            product_type=product_type,
            category=category,
            neck_type=neck_type,
            fabric=fabric,
            size=size,
            average_price=0.0,
            vendor_count=0
        )
        db.session.add(product)
        db.session.flush()  # Get the ID without committing
    
    return product


def recalculate_all_product_averages_from_files():
    """
    Recalculate average prices for all products by parsing all approved quotation files.
    This is the source of truth for average pricing.
    Returns the number of products updated.
    """
    # Get all approved submissions
    approved_submissions = VendorQuotationSubmission.query.filter_by(status='approved').all()
    
    # Collect all prices by product key
    # Structure: { (product_type, category, neck_type, fabric, size): { vendor_id: price } }
    product_vendor_prices = {}
    
    for submission in approved_submissions:
        if not submission.quotation_file:
            continue
            
        quotation_data = parse_quotation_file_data(
            submission.quotation_file,
            submission.quotation_filename,
            submission.quotation_mimetype
        )
        
        if not quotation_data:
            continue
        
        for item in quotation_data:
            product_type = str(item.get('product_type', '')).strip()
            category = str(item.get('category', '')).strip()
            neck_type = str(item.get('neck_type', 'Standard')).strip() or 'Standard'
            fabric = str(item.get('fabric', item.get('fabric_type', 'Cotton'))).strip() or 'Cotton'
            size = str(item.get('size', 'M')).strip() or 'M'
            
            try:
                base_cost = float(item.get('base_cost', 0))
            except (ValueError, TypeError):
                continue
            
            if base_cost <= 0 or not product_type or not category:
                continue
            
            key = (product_type, category, neck_type, fabric, size)
            
            if key not in product_vendor_prices:
                product_vendor_prices[key] = {}
            
            # Store vendor's price (last price wins if multiple entries)
            product_vendor_prices[key][submission.vendor_id] = base_cost
    
    # Update ProductCatalog with new averages
    products_updated = 0
    
    for (product_type, category, neck_type, fabric, size), vendor_prices in product_vendor_prices.items():
        product = find_or_create_product_catalog(product_type, category, neck_type, fabric, size)
        
        if product:
            all_prices = list(vendor_prices.values())
            avg_price = sum(all_prices) / len(all_prices)
            
            product.average_price = round(avg_price, 2)
            product.final_price = round(avg_price * 1.40, 2)
            product.vendor_count = len(vendor_prices)
            product.updated_at = datetime.utcnow()
            products_updated += 1
    
    db.session.commit()
    return products_updated


def recalculate_product_average_price(product_id):
    """
    Recalculate the average price for a specific product.
    Wrapper that triggers full recalculation.
    """
    recalculate_all_product_averages_from_files()
    product = ProductCatalog.query.get(product_id)
    return product.average_price if product else None


def recalculate_all_product_averages():
    """
    Recalculate average prices for ALL products in the catalog.
    Alias for recalculate_all_product_averages_from_files.
    """
    return recalculate_all_product_averages_from_files()

@app.route('/admin/quotation-submissions/<int:submission_id>/reject', methods=['POST'])
@require_role('admin')
def reject_quotation_submission(submission_id):
    """Admin rejects quotation submission"""
    data = request.json
    remarks = data.get('remarks', 'Quotation rejected')
    
    submission = VendorQuotationSubmission.query.get(submission_id)
    if not submission:
        return jsonify({"error": "Submission not found"}), 404
    
    submission.status = 'rejected'
    submission.admin_remarks = remarks
    submission.reviewed_at = datetime.utcnow()
    
    # Create notification
    notif = Notification(
        user_id=submission.vendor_id,
        user_type='vendor',
        title='Quotation Rejected',
        message=f'Your quotation was rejected. Reason: {remarks}. Please re-submit.',
        type='verification'
    )
    db.session.add(notif)
    
    db.session.commit()
    return jsonify({"message": "Quotation rejected"}), 200

@app.route('/vendor/notifications/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_notifications(vendor_id):
    notifs = Notification.query.filter_by(user_id=vendor_id, user_type='vendor').order_by(Notification.created_at.desc()).all()
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifs]), 200

@app.route('/vendor/notifications/<int:notif_id>/read', methods=['POST'])
@require_role('vendor')
def mark_notification_read(notif_id):
    notif = Notification.query.get(notif_id)
    if notif:
        notif.is_read = True
        db.session.commit()
    return jsonify({"message": "Marked as read"}), 200


@app.route('/vendor/new-orders/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_new_orders(vendor_id):
    """Get orders assigned to a vendor that are not yet accepted"""
    try:
        orders = Order.query.filter_by(
            selected_vendor_id=vendor_id,
            status='assigned'
        ).all()
        
        result = []
        for o in orders:
            # Join with customer to get more details if needed
            customer = Customer.query.get(o.customer_id)
            result.append({
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": o.id,
                "customerName": customer.username if customer else "Unknown",
                "productType": o.product_type,
                "color": o.color,
                "size": o.sample_size or "N/A",
                "quantity": o.quantity,
                "customization": {
                    "printType": o.print_type,
                    "neckType": o.neck_type,
                    "fabric": o.fabric
                },
                "deadline": o.delivery_date,
                "assignedDate": o.created_at.isoformat() if o.created_at else None,
                "address": f"{o.address_line1}, {o.city}, {o.pincode}"
            })
            
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")



@app.route('/vendor/dashboard-stats/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_dashboard_stats(vendor_id):
    """Get summary statistics for vendor dashboard"""
    try:
        # Count orders by status
        new_orders = Order.query.filter_by(selected_vendor_id=vendor_id, status='assigned').count()
        
        production_statuses = ['accepted_by_vendor', 'material_prep', 'printing', 'printing_completed', 'quality_check']
        in_production = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(production_statuses)
        ).count()
        
        ready_dispatch = Order.query.filter_by(selected_vendor_id=vendor_id, status='packed_ready').count()
        
        completed = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.like('completed%')
        ).count()
        
        return jsonify({
            "newOrders": new_orders,
            "inProduction": in_production,
            "readyForDispatch": ready_dispatch,
            "completed": completed
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/admin/production-orders', methods=['GET'])
@require_role('admin')
def get_admin_production_orders():
    """Get all orders currently in production across all vendors"""
    try:
        production_statuses = [
            'assigned',
            'accepted_by_vendor', 
            'in_production', 
            'material_prep', 
            'printing', 
            'printing_completed', 
            'quality_check', 
            'packed_ready'
        ]
        
        orders = Order.query.filter(
            Order.status.in_(production_statuses),
            Order.selected_vendor_id.isnot(None)
        ).all()
        
        result = []
        for o in orders:
            vendor = Vendor.query.get(o.selected_vendor_id)
            
            # Progress calculation
            status_order = ['assigned', 'accepted_by_vendor', 'material_prep', 'printing', 'printing_completed', 'quality_check', 'packed_ready']
            try:
                # Use in_production as an alias for material_prep or general phase
                current_status = o.status
                if current_status == 'in_production':
                    current_status = 'material_prep'
                idx = status_order.index(current_status) if current_status in status_order else 0
                progress = int(((idx + 1) / len(status_order)) * 100)
            except:
                progress = 0
                
            result.append({
                "id": o.id,
                "vendor": vendor.business_name or vendor.username if vendor else "Unknown",
                "stage": o.status.replace('_', ' ').title(),
                "deadline": o.delivery_date or "N/A",
                "progress": progress
            })
            
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/in-production-orders/<int:vendor_id>', methods=['GET'])
@require_self_or_role('vendor_id', 'admin')
def get_vendor_in_production_orders(vendor_id):
    """Get orders that are in production or accepted by the vendor"""
    try:
        # We include 'accepted_by_vendor' and any other production stages
        # For now, let's include 'accepted_by_vendor', 'in_production', 'material_prep', 'printing', etc.
        # Basically anything assigned to the vendor that is NOT 'assigned' (which is for New Orders)
        # and NOT 'delivered'/'completed'.
        
        production_statuses = [
            'accepted_by_vendor', 
            'in_production', 
            'material_prep', 
            'printing', 
            'printing_completed', 
            'quality_check', 
            'packed_ready'
        ]
        
        orders = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(production_statuses)
        ).all()
        
        result = []
        for o in orders:
            customer = Customer.query.get(o.customer_id)
            
            # Map DB status to frontend PRODUCTION_STAGES ID if needed
            # For simplicity, we can use the status column directly if we align them
            current_stage = 'accepted'
            if o.status == 'accepted_by_vendor': current_stage = 'accepted'
            elif o.status == 'material_prep': current_stage = 'material'
            elif o.status == 'printing': current_stage = 'printing'
            elif o.status == 'printing_completed': current_stage = 'completed'
            elif o.status == 'quality_check': current_stage = 'quality'
            elif o.status == 'packed_ready': current_stage = 'packed'
            elif o.status == 'in_production': current_stage = 'material' # Fallback
            
            result.append({
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": o.id,
                "customerName": customer.username if customer else "Unknown",
                "productType": o.product_type,
                "quantity": o.quantity,
                "currentStage": current_stage,
                "deadline": o.delivery_date,
                "notes": o.feedback_comment or "", # Repurposing or use another field if available
                "photos": [] # Logic for photos can be added later
            })
            
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

def calculate_distance(lat1, lon1, lat2, lon2):
    """Haversine formula to calculate distance between two points in km"""
    if None in [lat1, lon1, lat2, lon2]:
        return float('inf')
    R = 6371  # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def auto_assign_rider(order):
    """Find and assign the nearest online and free approved rider"""
    try:
        # 0. Check if order is already assigned
        existing_assignment = DeliveryLog.query.filter(
            DeliveryLog.order_id == order.id,
            DeliveryLog.status.notin_(['failed', 'returned', 'cancelled'])
        ).first()
        
        if existing_assignment:
            return True, "Already assigned"

        # 1. Get Vendor Location
        vendor = Vendor.query.get(order.selected_vendor_id)
        if not vendor or vendor.latitude is None or vendor.longitude is None:
            return False, "Vendor location not available"

        # 2. Find Online and Approved/Active Riders
        online_riders = Rider.query.filter(
            (Rider.is_online == True),
            (Rider.verification_status.in_(['approved', 'active']))
        ).all()
        
        available_riders = []
        for r in online_riders:
            # Check if rider has any active deliveries in logs
            # We assume a rider is free if they don't have an 'assigned', 'picked_up', etc. status
            # Statuses that imply "Free": delivered, failed, returned, cancelled
            active_delivery = DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == r.id),
                (DeliveryLog.status.notin_(['delivered', 'failed', 'returned', 'cancelled']))
            ).first()
            
            if not active_delivery:
                dist = calculate_distance(vendor.latitude, vendor.longitude, r.latitude, r.longitude)
                available_riders.append((r, dist))
        
        if not available_riders:
            # Notify admin about failure
            admin_notif = Notification(
                user_id=1,
                user_type='admin',
                title='Auto-Assignment Failed',
                message=f'No online riders available nearby Vendor #{vendor.id} for Order ORD-{order.id}. Manual assignment required.',
                type='order'
            )
            db.session.add(admin_notif)
            db.session.commit()
            return False, "No online riders available nearby"
            
        # 3. Pick the closest one
        available_riders.sort(key=lambda x: x[1])
        nearest_rider, distance = available_riders[0]
        
        # 4. Create DeliveryLog entry
        customer = Customer.query.get(order.customer_id)
        new_assignment = DeliveryLog(
            order_id=order.id,
            assigned_rider_id=nearest_rider.id,
            vendor_address=vendor.address,
            vendor_contact=vendor.phone,
            customer_address=f"{order.address_line1}, {order.address_line2 or ''}, {order.city}, {order.state}, {order.pincode}",
            customer_contact=customer.phone if customer else "N/A",
            status='assigned',
            assigned_at=datetime.utcnow()
        )
        db.session.add(new_assignment)
        
        # 5. Notify Rider
        notif = Notification(
            user_id=nearest_rider.id,
            user_type='rider',
            title='New Delivery Assigned',
            message=f'You have been automatically assigned to Order ORD-{order.id}. Pickup from {vendor.business_name}.',
            type='order'
        )
        db.session.add(notif)
        
        # 6. Change Order Status to something indicating rider assignment?
        # Usually 'packed_ready' is fine, but we might want 'searching_rider' vs 'rider_assigned'
        # For now, we'll keep it at packed_ready and the rider app will show it.
        
        db.session.commit()
        return True, f"Assigned to {nearest_rider.name}"
        
    except Exception as e:
        db.session.rollback()
        log_error(e, {"function": "assign_rider_proximity"})
        return False, "Failed to assign rider. Please try again."

@app.route('/vendor/update-production-stage', methods=['POST'])
@require_role('vendor')
def update_production_stage():
    """Vendor updates the production stage of an order"""
    data = request.json
    order_id = data.get('order_id')
    vendor_id = data.get('vendor_id')
    stage_id = data.get('stage_id') # 'accepted', 'material', 'printing', etc.
    notes = data.get('notes', '')
    
    if not all([order_id, vendor_id, stage_id]):
        return jsonify({"error": "Missing required data"}), 400
        
    try:
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
            
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
            
        if order.selected_vendor_id != int(vendor_id):
            return jsonify({"error": "Unauthorized"}), 403
            
        # Map frontend stage_id to DB status
        status_map = {
            'accepted': 'accepted_by_vendor',
            'material': 'material_prep',
            'printing': 'printing',
            'completed': 'printing_completed',
            'quality': 'quality_check',
            'packed': 'packed_ready',
            'dispatched': 'dispatched',
            'delivered': 'delivered'
        }
        
        # Human-readable labels for notifications
        stage_labels = {
            'accepted': 'Order Accepted',
            'material': 'Material Preparation',
            'printing': 'Printing In Progress',
            'completed': 'Printing Completed',
            'quality': 'Quality Check',
            'packed': 'Packed & Ready for Dispatch',
            'dispatched': 'Order Dispatched',
            'delivered': 'Order Delivered'
        }
        
        new_status = status_map.get(stage_id, 'in_production')
        stage_label = stage_labels.get(stage_id, 'In Production')
        order.status = new_status
        
        # Record status history for tracking
        status_record = OrderStatusHistory(
            order_id=order.id,
            status=new_status,
            status_label=stage_label,
            changed_by_type='vendor',
            changed_by_id=int(vendor_id),
            notes=notes
        )
        db.session.add(status_record)
        
        db.session.commit()
        
        # --- Notify Admin ---
        admin_notif = Notification(
            user_id=1,  # Primary admin
            user_type='admin',
            title=f'Production Update: ORD-{order.id}',
            message=f'Order ORD-{order.id} has progressed to "{stage_label}". Vendor ID: {vendor_id}.',
            type='order'
        )
        db.session.add(admin_notif)
        
        # --- Notify Customer ---
        customer_notif = Notification(
            user_id=order.customer_id,
            user_type='customer',
            title=f'Your Order Update',
            message=f'Great news! Your order ORD-{order.id} is now in "{stage_label}" stage.',
            type='order'
        )
        db.session.add(customer_notif)
        
        db.session.commit()
        
        # --- Auto-assign Rider if Packed & Ready ---
        if new_status == 'packed_ready':
            success, message = auto_assign_rider(order)
            # We don't block the response if auto-assign fails, but it will be logged
        
        return jsonify({"message": "Production stage updated successfully", "new_status": new_status}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/move-to-production', methods=['POST'])
@require_role('vendor')
def vendor_move_to_production():
    """Vendor moves an assigned order directly to production"""
    data = request.json
    order_id = data.get('order_id')
    vendor_id = data.get('vendor_id')
    
    if not order_id or not vendor_id:
        return jsonify({"error": "Missing order_id or vendor_id"}), 400
        
    try:
        # Handle ORD- prefix if present
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
            
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
            
        if order.selected_vendor_id != int(vendor_id):
            return jsonify({"error": "This order is not assigned to you"}), 403
            
        # Move directly to in_production as per new requirement
        order.status = 'in_production'
        
        # Update formal assignment record
        assignment = VendorOrderAssignment.query.filter_by(order_id=actual_order_id, vendor_id=int(vendor_id)).first()
        if assignment:
            assignment.status = 'accepted'
            assignment.responded_at = datetime.utcnow()
        
        # Record status history for tracking
        status_record = OrderStatusHistory(
            order_id=actual_order_id,
            status='in_production',
            status_label='In Production',
            changed_by_type='vendor',
            changed_by_id=int(vendor_id),
            notes='Vendor moved order directly to production'
        )
        db.session.add(status_record)
            
        db.session.commit()
        
        return jsonify({"message": "Order moved to production successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/vendor/reject-order', methods=['POST'])
@require_role('vendor')
def vendor_reject_order():
    """Vendor rejects an assigned order"""
    data = request.json
    order_id = data.get('order_id')
    vendor_id = data.get('vendor_id')
    reason = data.get('reason', 'No reason provided')
    
    if not order_id or not vendor_id:
        return jsonify({"error": "Missing order_id or vendor_id"}), 400
        
    try:
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
            
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
            
        if order.selected_vendor_id != int(vendor_id):
            return jsonify({"error": "This order is not assigned to you"}), 403
            
        order.status = 'rejected_by_vendor'
        order.selected_vendor_id = None # Back to unassigned
        
        # Update formal assignment record
        assignment = VendorOrderAssignment.query.filter_by(order_id=actual_order_id, vendor_id=int(vendor_id)).first()
        if assignment:
            assignment.status = 'rejected'
            assignment.rejection_reason = reason
            assignment.responded_at = datetime.utcnow()
        
        # Create notification for admin
        notif = Notification(
            user_id=1, # Admin
            user_type='admin',
            title='Order Rejected by Vendor',
            message=f'Vendor has rejected order #{actual_order_id}. Reason: {reason}',
            type='order'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return jsonify({"message": "Order rejected successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/admin/verified-vendors', methods=['GET'])
@require_role('admin')
def get_verified_vendors():
    """Get all verified vendors (approved or active status)"""
    vendors = Vendor.query.filter(
        Vendor.verification_status.in_(['approved', 'active'])
    ).all()
    
    result = []
    for v in vendors:
        result.append({
            "id": v.id,
            "name": v.business_name or v.username or "Unknown",
            "businessType": v.business_type or "N/A",
            "email": v.email or "N/A",
            "phone": v.phone or "N/A",
            "address": v.address or "N/A",
            "status": v.verification_status or "unknown",
            "commissionRate": v.commission_rate if v.commission_rate is not None else 0,
            "paymentCycle": v.payment_cycle or "monthly",
            "serviceZone": v.service_zone or "N/A",
            "joinedDate": v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A"
        })
    
    return jsonify(result), 200


# ==========================================
# PRODUCT CATALOG & AVERAGE PRICE ENDPOINTS
# ==========================================

@app.route('/admin/product-catalog', methods=['GET'])
@require_role('admin')
def get_product_catalog():
    """Get all products in the catalog with their average prices"""
    try:
        products = ProductCatalog.query.all()
        
        result = []
        for p in products:
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': p.average_price,
                'vendor_count': p.vendor_count,
                'notes': p.notes,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/quotations/stats', methods=['GET'])
@require_role('admin')
def get_quotation_stats():
    """
    Get statistics about vendor quotations and submissions.
    Used by the average prices page to show summary statistics.
    """
    try:
        # Count total quotations
        total_quotations = VendorQuotation.query.count()
        
        # Count vendors with quotations
        vendors_with_quotations = db.session.query(VendorQuotation.vendor_id).distinct().count()
        
        # Count pending submissions
        pending_submissions = VendorQuotationSubmission.query.filter_by(status='pending').count()
        
        # Count approved submissions
        approved_submissions = VendorQuotationSubmission.query.filter_by(status='approved').count()
        
        return jsonify({
            'total_quotations': total_quotations,
            'total_vendors_with_quotations': vendors_with_quotations,
            'pending_submissions': pending_submissions,
            'approved_submissions': approved_submissions
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/average-prices', methods=['GET'])
@require_role('admin')
def get_average_prices():
    """
    Get average prices grouped by product type, category, and neck type.
    This provides a summary view of pricing across all vendors.
    """
    try:
        # Get all products with their quotation counts
        products = ProductCatalog.query.filter(ProductCatalog.vendor_count > 0).all()
        
        result = []
        for p in products:
            # Calculate min and max prices from vendor quotations
            quotations = VendorQuotation.query.filter_by(product_id=p.id, status='approved').all()
            min_price = min([q.base_cost for q in quotations], default=p.average_price)
            max_price = max([q.base_cost for q in quotations], default=p.average_price)
            
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': p.average_price,
                'min_price': min_price,
                'max_price': max_price,
                'vendor_count': p.vendor_count,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/recalculate-averages', methods=['POST'])
@require_role('admin')
def admin_recalculate_averages():
    """
    Manually trigger recalculation of all product averages.
    Useful for maintenance or after bulk data changes.
    """
    try:
        updated_count = recalculate_all_product_averages()
        return jsonify({
            "message": f"Successfully recalculated averages for {updated_count} products",
            "updated_count": updated_count
        }), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/api/product-price/<int:product_id>', methods=['GET'])
@require_auth
def get_product_price(product_id):
    """Get the final price for a specific product"""
    try:
        product = ProductCatalog.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        return jsonify({
            'id': product.id,
            'product_type': product.product_type,
            'category': product.category,
            'average_price': product.final_price, # Send final_price as the price
            'vendor_count': product.vendor_count
        }), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/vendor-quotations/<int:vendor_id>', methods=['GET'])
@require_role('admin')
def get_vendor_quotations(vendor_id):
    """Get all quotations submitted by a specific vendor"""
    try:
        quotations = VendorQuotation.query.filter_by(vendor_id=vendor_id).all()
        
        result = []
        for q in quotations:
            product = ProductCatalog.query.get(q.product_id)
            result.append({
                'id': q.id,
                'vendor_id': q.vendor_id,
                'product_id': q.product_id,
                'product_type': product.product_type if product else 'Unknown',
                'category': product.category if product else 'Unknown',
                'neck_type': product.neck_type if product else 'Unknown',
                'fabric': product.fabric if product else 'Unknown',
                'size': product.size if product else 'Unknown',
                'base_cost': q.base_cost,
                'status': q.status,
                'created_at': q.created_at.isoformat() if q.created_at else None,
                'updated_at': q.updated_at.isoformat() if q.updated_at else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

# ==========================================
# RIDER VERIFICATION ENDPOINTS
# ==========================================

@app.route('/rider/verification/status/<int:rider_id>', methods=['GET'])
@require_self_or_role('rider_id', 'admin')
def get_rider_verification_status(rider_id):
    """Get rider's verification status and documents"""
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
    
    # Get or create document row
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if not doc_row:
        doc_row = RiderDocument(rider_id=rider_id)
        db.session.add(doc_row)
        db.session.commit()
    
    # Build documents dict
    documents = {}
    for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
        meta = getattr(doc_row, f"{doc_type}_meta")
        doc_data = {}
        
        if meta:
            doc_data = {
                'status': meta.get('status', 'pending'),
                'fileName': meta.get('filename'),
                'fileSize': meta.get('size'),
                'uploadedDate': meta.get('uploaded_at'),
                'adminRemarks': meta.get('remarks', '')
            }
        else:
            doc_data = {
                'status': 'pending',
                'fileName': None,
                'fileSize': None,
                'uploadedDate': None,
                'adminRemarks': ''
            }
            
        # Add manual fields
        if doc_type == 'aadhar': doc_data['aadhar_number'] = doc_row.aadhar_number
        if doc_type == 'pan': doc_data['pan_number'] = doc_row.pan_number
        if doc_type == 'dl': 
            doc_data['dl_number'] = doc_row.dl_number
            doc_data['dl_name'] = doc_row.dl_name
            doc_data['dl_validity'] = doc_row.dl_validity
            
        if doc_type == 'vehicle_rc': doc_data['vehicle_rc_number'] = doc_row.vehicle_rc_number
        if doc_type == 'insurance': doc_data['insurance_policy_number'] = doc_row.insurance_policy_number
        
        if doc_type == 'bank':
            doc_data['bank_account_number'] = doc_row.bank_account_number
            doc_data['bank_holder_name'] = doc_row.bank_holder_name
            doc_data['bank_branch'] = doc_row.bank_branch
            doc_data['ifsc_code'] = doc_row.ifsc_code
        
        documents[doc_type] = doc_data
    
    return jsonify({
        "status": rider.verification_status or "not-submitted",
        "documents": documents,
        "adminRemarks": rider.admin_remarks or ""
    }), 200

@app.route('/rider/verification/upload', methods=['POST'])
@require_role('rider')
def upload_rider_document():
    """Upload a rider verification document"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    rider_id = request.form.get('rider_id')
    doc_type = request.form.get('doc_type')
    
    if not file or not rider_id or not doc_type:
        return jsonify({"error": "Missing required data"}), 400
    
    # Validate document type
    valid_types = ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']
    if doc_type not in valid_types:
        return jsonify({"error": "Invalid document type"}), 400
    
    try:
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Get or create document row
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        if not doc_row:
            doc_row = RiderDocument(rider_id=rider_id)
            db.session.add(doc_row)
        
        # Validate and save file using secure upload utility
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/rider/verification/upload',
            subfolder='rider',
            user_id=int(rider_id),
            doc_type=doc_type,
            scan_virus=False  # Set to True if ClamAV is configured
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Delete old file if exists
        old_path = getattr(doc_row, doc_type, None)
        if old_path:
            delete_file(old_path)
        
        # Store file path instead of file data
        setattr(doc_row, doc_type, file_info['path'])
        
        # Store metadata
        meta = {
            'filename': file_info['filename'],
            'original_filename': file_info['original_filename'],
            'mimetype': file_info['mimetype'],
            'size': file_info['size'],
            'uploaded_at': datetime.utcnow().isoformat(),
            'status': 'uploaded'
        }
        setattr(doc_row, f"{doc_type}_meta", meta)
        
        # Save manual fields if provided during upload
        if doc_type == 'aadhar' and request.form.get('aadhar_number'):
            doc_row.aadhar_number = request.form.get('aadhar_number')
        if doc_type == 'pan' and request.form.get('pan_number'):
            doc_row.pan_number = request.form.get('pan_number')
        if doc_type == 'dl':
            if request.form.get('dl_number'): doc_row.dl_number = request.form.get('dl_number')
            if request.form.get('dl_name'): doc_row.dl_name = request.form.get('dl_name')
            if request.form.get('dl_validity'): doc_row.dl_validity = request.form.get('dl_validity')

        if doc_type == 'vehicle_rc' and request.form.get('vehicle_rc_number'):
            doc_row.vehicle_rc_number = request.form.get('vehicle_rc_number')
        if doc_type == 'insurance' and request.form.get('insurance_policy_number'):
            doc_row.insurance_policy_number = request.form.get('insurance_policy_number')
            
        if doc_type == 'bank':
            if request.form.get('bank_account_number'): doc_row.bank_account_number = request.form.get('bank_account_number')
            if request.form.get('bank_holder_name'): doc_row.bank_holder_name = request.form.get('bank_holder_name')
            if request.form.get('bank_branch'): doc_row.bank_branch = request.form.get('bank_branch')
            if request.form.get('ifsc_code'): doc_row.ifsc_code = request.form.get('ifsc_code')
        
        db.session.commit()
        
        return jsonify({
            "message": "Document uploaded successfully",
            "fileUrl": f"/rider/verification/document/{rider_id}/{doc_type}"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/verification/document/<int:rider_id>/<doc_type>', methods=['GET'])
@require_self_or_role('rider_id', 'admin')
def get_rider_document(rider_id, doc_type):
    """View a rider's document"""
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if not doc_row:
        return jsonify({"error": "No documents found"}), 404
    
    file_path = getattr(doc_row, doc_type)
    if not file_path:
        return jsonify({"error": "Document not found"}), 404
    
    # Get absolute file path
    from file_upload import get_file_path_from_db
    absolute_path = get_file_path_from_db(file_path)
    
    if not absolute_path or not os.path.exists(absolute_path):
        return jsonify({"error": "File not found on disk"}), 404
    
    meta = getattr(doc_row, f"{doc_type}_meta")
    mimetype = meta.get('mimetype', 'application/octet-stream') if meta else 'application/octet-stream'
    filename = meta.get('filename', f'{doc_type}.pdf') if meta else f'{doc_type}.pdf'
    
    return send_file(
        absolute_path,
        mimetype=mimetype,
        as_attachment=False,
        download_name=filename
    )

@app.route('/rider/verification/submit', methods=['POST'])
@require_role('rider')
def submit_rider_verification():
    """Submit rider verification for admin review"""
    data = request.json
    rider_id = data.get('rider_id')
    if rider_id:
        rider_id = int(rider_id)

    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
        
    # Update manual fields in RiderDocument
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if not doc_row:
        doc_row = RiderDocument(rider_id=rider_id)
        db.session.add(doc_row)
        
    if data.get('aadhar_number'): doc_row.aadhar_number = data.get('aadhar_number')
    if data.get('pan_number'): doc_row.pan_number = data.get('pan_number')
    
    # DL fields
    if data.get('dl_number'): doc_row.dl_number = data.get('dl_number')
    if data.get('dl_name'): doc_row.dl_name = data.get('dl_name')
    if data.get('dl_validity'): doc_row.dl_validity = data.get('dl_validity')
    
    if data.get('vehicle_rc_number'): doc_row.vehicle_rc_number = data.get('vehicle_rc_number')
    if data.get('insurance_policy_number'): doc_row.insurance_policy_number = data.get('insurance_policy_number')
    
    # Bank fields
    if data.get('bank_account_number'): doc_row.bank_account_number = data.get('bank_account_number')
    if data.get('bank_holder_name'): doc_row.bank_holder_name = data.get('bank_holder_name')
    if data.get('bank_branch'): doc_row.bank_branch = data.get('bank_branch')
    if data.get('ifsc_code'): doc_row.ifsc_code = data.get('ifsc_code')
        
    rider.verification_status = 'pending'
    db.session.commit()
    
    return jsonify({"message": "Verification submitted successfully"}), 200

@app.route('/admin/rider-requests', methods=['GET'])
@require_role('admin')
def get_rider_requests():
    """Get all rider verification requests (pending, under-review, rejected)"""
    riders = Rider.query.filter(
        Rider.verification_status.in_(['pending', 'under-review'])
    ).all()
    
    
    result = []
    for r in riders:
        try:
            # Fetch documents for this rider
            doc_row = RiderDocument.query.filter_by(rider_id=r.id).first()
            documents = {}
            if doc_row:
                for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                    if hasattr(doc_row, f"{doc_type}_meta"):
                        meta = getattr(doc_row, f"{doc_type}_meta")
                        if meta:
                            doc_data = {
                                'status': meta.get('status', 'pending'),
                                'fileName': meta.get('filename'),
                                'fileSize': meta.get('size'),
                                'uploadedDate': meta.get('uploaded_at')
                            }
                            
                            # Add manual fields
                            if doc_type == 'aadhar': doc_data['aadhar_number'] = doc_row.aadhar_number
                            if doc_type == 'pan': doc_data['pan_number'] = doc_row.pan_number
                            
                            if doc_type == 'dl': 
                                doc_data['dl_number'] = doc_row.dl_number
                                doc_data['dl_name'] = doc_row.dl_name
                                doc_data['dl_validity'] = doc_row.dl_validity
                                
                            if doc_type == 'vehicle_rc': doc_data['vehicle_rc_number'] = doc_row.vehicle_rc_number
                            if doc_type == 'insurance': doc_data['insurance_policy_number'] = doc_row.insurance_policy_number
                            
                            if doc_type == 'bank':
                                doc_data['bank_account_number'] = doc_row.bank_account_number
                                doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                doc_data['bank_branch'] = doc_row.bank_branch
                                doc_data['ifsc_code'] = doc_row.ifsc_code
                            
                            documents[doc_type] = doc_data
            
            result.append({
                "id": r.id,
                "name": r.name or "Unknown",
                "email": r.email or "N/A",
                "phone": r.phone or "N/A",
                "vehicleType": r.vehicle_type or "N/A",
                "vehicleNumber": r.vehicle_number or "N/A",
                "serviceZone": r.service_zone or "N/A",
                "submitted": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A",
                "status": r.verification_status or "pending",
                "documents": documents,
                "adminRemarks": r.admin_remarks or ""
            })
        except Exception as e:
            log_error_with_context(e, {"rider_id": r.id, "endpoint": request.path, "action": "processing_rider_data"})
        
    return jsonify(result), 200

@app.route('/admin/rejected-riders', methods=['GET'])
@require_role('admin')
def get_rejected_riders():
    """Get only rejected riders"""
    riders = Rider.query.filter_by(verification_status='rejected').all()
    
    result = []
    for r in riders:
        try:
            # Fetch documents for this rider
            doc_row = RiderDocument.query.filter_by(rider_id=r.id).first()
            documents = {}
            if doc_row:
                for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                    if hasattr(doc_row, f"{doc_type}_meta"):
                        meta = getattr(doc_row, f"{doc_type}_meta")
                        if meta:
                            doc_data = {
                                'status': meta.get('status', 'pending'),
                                'fileName': meta.get('filename'),
                                'fileSize': meta.get('size'),
                                'uploadedDate': meta.get('uploaded_at')
                            }
                            
                            # Add manual fields
                            if doc_type == 'aadhar': doc_data['aadhar_number'] = doc_row.aadhar_number
                            if doc_type == 'pan': doc_data['pan_number'] = doc_row.pan_number
                            
                            if doc_type == 'dl': 
                                doc_data['dl_number'] = doc_row.dl_number
                                doc_data['dl_name'] = doc_row.dl_name
                                doc_data['dl_validity'] = doc_row.dl_validity
                                
                            if doc_type == 'vehicle_rc': doc_data['vehicle_rc_number'] = doc_row.vehicle_rc_number
                            if doc_type == 'insurance': doc_data['insurance_policy_number'] = doc_row.insurance_policy_number
                            
                            if doc_type == 'bank':
                                doc_data['bank_account_number'] = doc_row.bank_account_number
                                doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                doc_data['bank_branch'] = doc_row.bank_branch
                                doc_data['ifsc_code'] = doc_row.ifsc_code
                            
                            documents[doc_type] = doc_data
            
            result.append({
                "id": r.id,
                "name": r.name or "Unknown",
                "email": r.email or "N/A",
                "phone": r.phone or "N/A",
                "vehicleType": r.vehicle_type or "N/A",
                "vehicleNumber": r.vehicle_number or "N/A",
                "serviceZone": r.service_zone or "N/A",
                "submitted": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A",
                "status": r.verification_status or "pending",
                "documents": documents,
                "adminRemarks": r.admin_remarks or ""
            })
        except Exception as e:
            log_error_with_context(e, {"rider_id": r.id, "endpoint": request.path, "action": "processing_rider_data"})
        
    return jsonify(result), 200

@app.route('/admin/vendor-requests/<int:vendor_id>/document/<doc_type>/status', methods=['POST'])
@require_role('admin')
def update_vendor_document_status(vendor_id, doc_type):
    """Update status of a specific vendor document"""
    data = request.json
    status = data.get('status')
    reason = data.get('reason')
    
    vendor = Vendor.query.get(vendor_id)
    if not vendor:
        return jsonify({"error": "Vendor not found"}), 404
        
    doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
    if not doc_row:
        return jsonify({"error": "Documents not initialized"}), 404
        
    if not hasattr(doc_row, f"{doc_type}_meta"):
        return jsonify({"error": "Invalid document type"}), 400
        
    # Get current meta
    meta = getattr(doc_row, f"{doc_type}_meta") or {}
    
    # Update status
    meta['status'] = status
    if status == 'rejected':
        if reason:
            meta['remarks'] = reason
        # Auto-reject the application to enable re-upload
        vendor.verification_status = 'rejected'
        if not vendor.admin_remarks:
             vendor.admin_remarks = "Please review rejected documents."
    elif status == 'approved':
         meta['remarks'] = None # Clear remarks on approval
         
    # Save back
    setattr(doc_row, f"{doc_type}_meta", meta)
    
    db.session.commit()
    
    return jsonify({"message": "Document status updated"}), 200

@app.route('/admin/rider-requests/<int:rider_id>/document/<doc_type>/status', methods=['POST'])
@require_role('admin')
def update_rider_document_status(rider_id, doc_type):
    """Update status of a specific rider document"""
    data = request.json
    status = data.get('status')
    reason = data.get('reason')
    
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
        
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if not doc_row:
        return jsonify({"error": "Documents not initialized"}), 404
        
    if not hasattr(doc_row, f"{doc_type}_meta"):
        return jsonify({"error": "Invalid document type"}), 400
        
    # Get current meta
    meta = getattr(doc_row, f"{doc_type}_meta") or {}
    
    # Update status
    meta['status'] = status
    if status == 'rejected':
        if reason:
            meta['remarks'] = reason
        rider.verification_status = 'rejected'
        if not rider.admin_remarks:
            rider.admin_remarks = "Please review rejected documents."
    elif status == 'approved':
         meta['remarks'] = None
         
    setattr(doc_row, f"{doc_type}_meta", meta)
    db.session.commit()
    
    return jsonify({"message": "Document status updated"}), 200

@app.route('/admin/rider-requests/<int:rider_id>/reject', methods=['POST'])
@require_role('admin')
def reject_rider(rider_id):
    """Reject a rider verification request"""
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
    
    data = request.json
    global_reason = data.get('reason', 'Verification rejected')
    rejected_docs = data.get('rejected_documents', {})

    rider.verification_status = 'rejected'
    rider.admin_remarks = global_reason
    
    
    # Update document statuses
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if doc_row:
        if rejected_docs:
            for doc_type, reason in rejected_docs.items():
                if hasattr(doc_row, f"{doc_type}_meta"):
                    current_meta = getattr(doc_row, f"{doc_type}_meta")
                    meta = dict(current_meta) if current_meta else {}
                    meta['status'] = 'rejected'
                    meta['remarks'] = reason
                    setattr(doc_row, f"{doc_type}_meta", meta)
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(doc_row, f"{doc_type}_meta")
        else:
             # Do NOT auto-reject all documents. 
             # Only global status changes to 'rejected'.
             pass
    
    db.session.commit()
    
    # Send email notification
    try:
        # Assuming 'mail' and 'Message' are imported from Flask-Mail or similar
        # from flask_mail import Message
        # msg = Message("Rider Application Rejected",
        #             recipients=[rider.email])
        # msg.body = f"Hello {rider.name},\n\nYour application has been rejected. Reason: {global_reason}\n\nPlease update your details and re-apply."
        # mail.send(msg) 
        pass # Placeholder for email sending logic
    except Exception:
        pass
    
    return jsonify({"message": "Rider rejected successfully"}), 200

@app.route('/admin/rider-requests/<int:rider_id>/approve', methods=['POST'])
@require_role('admin')
def approve_rider(rider_id):
    """Approve a rider verification request"""
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
    
    rider.verification_status = 'active'
    rider.admin_remarks = None
    
    # Update all document statuses to approved
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if doc_row:
        for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance']:
            meta = getattr(doc_row, f"{doc_type}_meta")
            if meta:
                meta['status'] = 'approved'
                setattr(doc_row, f"{doc_type}_meta", meta)
    
    # Create notification
    notif = Notification(
        user_id=rider.id,
        user_type='rider',
        title='Verification Approved',
        message='Your verification has been approved. Your account is now active.',
        type='verification'
    )
    db.session.add(notif)
    
    db.session.commit()
    return jsonify({"message": "Rider approved successfully"}), 200



@app.route('/orders/<int:order_id>/request-bulk', methods=['POST'])
@require_role('customer')
def request_bulk_order(order_id):
    """Customer requests bulk order after sample satisfaction"""
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
            
        # Optional: Check if status is correct?
        # if order.status != 'delivered':
        #    return jsonify({"error": "Order must be delivered first"}), 400

        # Create Admin Notification
        admin_notif = Notification(
            user_id=1, # Admin
            user_type='admin',
            title='Bulk Order Request',
            message=f'Customer has approved sample for Order #{order.id} and requested BULK production. Please review.',
            type='order'
        )
        db.session.add(admin_notif)
        
        # Log in history
        history = OrderStatusHistory(
            order_id=order.id,
            status='bulk_requested',
            status_label='Bulk Order Requested',
            changed_by_type='customer',
            changed_by_id=order.customer_id,
            notes='Customer satisfied with sample. Requested bulk order.'
        )
        db.session.add(history)
        
        db.session.commit()
        return jsonify({"message": "Bulk order requested"}), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")
def delete_rider_request(rider_id):
    """Delete a rider verification request"""
    rider = Rider.query.get(rider_id)
    if not rider:
        return jsonify({"error": "Rider not found"}), 404
    
    # Delete all documents
    doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
    if doc_row:
        db.session.delete(doc_row)
    
    db.session.commit()
    return jsonify({"message": "Rider request deleted successfully"}), 200

@app.route('/admin/verified-riders', methods=['GET'])
@require_role('admin')
def get_verified_riders():
    """Get all verified riders (active or approved status)"""
    riders = Rider.query.filter(
        Rider.verification_status.in_(['active', 'approved'])
    ).all()
    
    result = []
    for r in riders:
        result.append({
            "id": r.id,
            "name": r.name or "Unknown",
            "email": r.email or "N/A",
            "phone": r.phone or "N/A",
            "vehicleType": r.vehicle_type or "N/A",
            "vehicleNumber": r.vehicle_number or "N/A",
            "serviceZone": r.service_zone or "N/A",
            "status": r.verification_status or "unknown",
            "totalDeliveries": r.total_deliveries or 0,
            "successfulDeliveries": r.successful_deliveries or 0,
            "averageRating": r.average_rating or 0.0,
            "totalEarnings": r.total_earnings or 0.0,
            "joinedDate": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A"
        })
    
    return jsonify(result), 200

@app.route('/rider/notifications/<int:rider_id>', methods=['GET'])
@require_self_or_role('rider_id', 'admin')
def get_rider_notifications(rider_id):
    """Get rider notifications"""
    notifs = Notification.query.filter_by(user_id=rider_id, user_type='rider').order_by(Notification.created_at.desc()).all()
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifs]), 200

@app.route('/rider/notifications', methods=['GET'])
@require_role('rider')
def get_rider_notifications_query():
    """Get rider notifications with query parameters"""
    rider_id = request.args.get('rider_id')
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    if not rider_id:
        return jsonify({"error": "rider_id is required"}), 400
    
    query = Notification.query.filter_by(user_id=int(rider_id), user_type='rider')
    
    if unread_only:
        query = query.filter_by(is_read=False)
    
    notifs = query.order_by(Notification.created_at.desc()).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifs]), 200


# =====================================================
# RIDER DELIVERY OPERATIONS
# =====================================================

@app.route('/rider/deliveries/assigned', methods=['GET', 'OPTIONS'])
@app.route('/rider/deliveries/assigned', methods=['GET', 'OPTIONS'], subdomain='rider')
@require_role('rider')
def get_rider_assigned_deliveries():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
    """Fetch all deliveries assigned to a specific rider"""
    rider_id = request.args.get('rider_id')
    if not rider_id:
        return jsonify({"error": "rider_id is required"}), 400
        
    try:
        # Filter for active/assigned deliveries
        deliveries = DeliveryLog.query.filter_by(assigned_rider_id=int(rider_id)).all()
        
        result = []
        for d in deliveries:
            order = Order.query.get(d.order_id)
            result.append({
                "id": d.id,
                "order_id": d.order_id,
                "status": d.status,
                "pickup": {
                    "address": d.vendor_address,
                    "contact": d.vendor_contact
                },
                "delivery": {
                    "address": d.customer_address,
                    "contact": d.customer_contact
                },
                "deadline": order.delivery_date if order and order.delivery_date else None,
                "is_urgent": False, # Basic logic
                "product_details": {
                    "type": order.category if order else "Items",
                    "quantity": order.quantity if order else 1
                }
            })
        
        return jsonify({"deliveries": result}), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/delivery/<int:delivery_id>/status', methods=['PUT'])
@require_role('rider')
def update_rider_delivery_status(delivery_id):
    """Update the status of a delivery and sync with Order status"""
    data = request.json
    status = data.get('status') # 'reached_vendor', 'picked_up', 'out_for_delivery', 'delivered'
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    delivery = DeliveryLog.query.get(delivery_id)
    if not delivery:
        return jsonify({"error": "Delivery not found"}), 404
        
    try:
        delivery.status = status
        
        # Record timestamp and GPS location based on status
        if status == 'reached_vendor':
            delivery.reached_vendor_at = datetime.utcnow()
            if latitude and longitude:
                delivery.current_latitude = latitude
                delivery.current_longitude = longitude
                delivery.last_location_update = datetime.utcnow()
        elif status == 'picked_up':
            delivery.picked_up_at = datetime.utcnow()
        elif status == 'out_for_delivery':
            delivery.out_for_delivery_at = datetime.utcnow()
        elif status == 'delivered':
            delivery.delivered_at = datetime.utcnow()
        
        order = Order.query.get(delivery.order_id)
        
        if order:
            if status == 'reached_vendor':
                order.status = 'reached_vendor'
                # Record status history
                history = OrderStatusHistory(
                    order_id=order.id,
                    status='reached_vendor',
                    status_label='Rider Reached Vendor',
                    changed_by_type='rider',
                    changed_by_id=delivery.assigned_rider_id,
                    notes='Rider has arrived at pickup location'
                )
                db.session.add(history)
            
            elif status == 'picked_up':
                order.status = 'picked_up'
                delivery.picked_up_at = datetime.utcnow()
                
                # Record status history
                history = OrderStatusHistory(
                    order_id=order.id,
                    status='picked_up',
                    status_label='Order Picked Up',
                    changed_by_type='rider',
                    changed_by_id=delivery.assigned_rider_id,
                    notes='Rider has picked up the order'
                )
                db.session.add(history)
                
            elif status == 'out_for_delivery':
                order.status = 'out_for_delivery'
                
                # Record status history
                history = OrderStatusHistory(
                    order_id=order.id,
                    status='out_for_delivery',
                    status_label='Out for Delivery',
                    changed_by_type='rider',
                    changed_by_id=delivery.assigned_rider_id,
                    notes='Rider is on the way to customer'
                )
                db.session.add(history)
                
            elif status == 'delivered':
                order.status = 'delivered'
                delivery.delivered_at = datetime.utcnow()
                delivery.delivery_time = datetime.utcnow()
                
                # Record status history
                history = OrderStatusHistory(
                    order_id=order.id,
                    status='delivered',
                    status_label='Order Delivered',
                    changed_by_type='rider',
                    changed_by_id=delivery.assigned_rider_id,
                    notes='Delivered by rider'
                )
                db.session.add(history)
        
        db.session.commit()
        return jsonify({"message": f"Delivery status updated to {status}"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/delivery/<int:delivery_id>/pickup-proof', methods=['POST'])
@require_role('rider')
def rider_upload_pickup_proof(delivery_id):
    """Upload proof image when picking up from vendor"""
    delivery = DeliveryLog.query.get(delivery_id)
    if not delivery:
        return jsonify({"error": "Delivery not found"}), 404
        
    file = request.files.get('proof_image')
    notes = request.form.get('notes', '')
    
    try:
        if file:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/rider/delivery',
                subfolder='rider',
                user_id=delivery.assigned_rider_id,
                doc_type='pickup_proof',
                scan_virus=False
            )
            if error:
                return jsonify({"error": error}), 400
            
            # Delete old file if exists
            if delivery.pickup_proof:
                delete_file(delivery.pickup_proof)
            
            delivery.pickup_proof = file_info['path']
            delivery.pickup_proof_filename = file_info['filename']
        
        delivery.notes = notes
        delivery.status = 'picked_up'
        delivery.picked_up_at = datetime.utcnow()
        
        order = Order.query.get(delivery.order_id)
        if order:
            order.status = 'picked_up'
            
            # Record status history
            history = OrderStatusHistory(
                order_id=order.id,
                status='picked_up',
                status_label='Order Picked Up',
                changed_by_type='rider',
                changed_by_id=delivery.assigned_rider_id,
                notes=f'Pickup proof uploaded. Notes: {notes}'
            )
            db.session.add(history)
            
        db.session.commit()
        return jsonify({"message": "Pickup proof uploaded and marked as picked up"}), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/delivery/<int:delivery_id>/delivery-proof', methods=['POST'])
@require_role('rider')
def rider_upload_delivery_proof(delivery_id):
    """Upload proof and complete delivery"""
    delivery = DeliveryLog.query.get(delivery_id)
    if not delivery:
        return jsonify({"error": "Delivery not found"}), 404
        
    file = request.files.get('proof_image')
    otp = request.form.get('otp', '')
    notes = request.form.get('notes', '')
    
    try:
        if file:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/rider/delivery',
                subfolder='rider',
                user_id=delivery.assigned_rider_id,
                doc_type='delivery_proof',
                scan_virus=False
            )
            if error:
                return jsonify({"error": error}), 400
            
            # Delete old file if exists
            if delivery.delivery_proof:
                delete_file(delivery.delivery_proof)
            
            delivery.delivery_proof = file_info['path']
            delivery.delivery_proof_filename = file_info['filename']
            
        delivery.status = 'delivered'
        delivery.delivered_at = datetime.utcnow()
        delivery.delivery_time = datetime.utcnow()
        delivery.notes = (delivery.notes or "") + f" | Delivery notes: {notes}"
        
        # Calculate mock earnings (e.g., 40 base + 10 bonus)
        delivery.base_payout = 40.0
        delivery.total_earning = 50.0
        delivery.payout_status = 'pending'
        
        order = Order.query.get(delivery.order_id)
        if order:
            order.status = 'delivered'
            # Add history
            history = OrderStatusHistory(
                order_id=order.id,
                status='delivered',
                status_label='Order Delivered',
                changed_by_type='rider',
                changed_by_id=delivery.assigned_rider_id
            )
            db.session.add(history)
            
        db.session.commit()
        return jsonify({
            "message": "Delivery completed successfully",
            "earnings": {"total": 50.0}
        }), 200
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/delivery/<int:delivery_id>/details', methods=['GET'])
@require_role('rider', 'admin', 'vendor', 'customer')
def get_delivery_details(delivery_id):
    """Get full delivery details for a specific delivery"""
    try:
        rider_id = request.args.get('rider_id')
        if not rider_id:
            return jsonify({"error": "Rider ID required"}), 400
        
        delivery = DeliveryLog.query.filter_by(
            id=delivery_id,
            assigned_rider_id=int(rider_id)
        ).first()
        
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        # Get order details
        order = Order.query.get(delivery.order_id)
        
        return jsonify({
            "id": delivery.id,
            "order_id": delivery.order_id,
            "status": delivery.status,
            "is_urgent": delivery.is_urgent or False,
            "pickup": {
                "address": delivery.vendor_address,
                "contact": delivery.vendor_contact
            },
            "delivery": {
                "address": delivery.customer_address,
                "contact": delivery.customer_contact
            },
            "product_details": {
                "type": order.category if order else "Items",
                "quantity": order.quantity if order else 1,
                "fabric": order.fabric if order else None,
                "color": order.color if order else None
            },
            "assigned_at": delivery.assigned_at.isoformat() if delivery.assigned_at else None,
            "reached_vendor_at": delivery.reached_vendor_at.isoformat() if delivery.reached_vendor_at else None,
            "picked_up_at": delivery.picked_up_at.isoformat() if delivery.picked_up_at else None,
            "out_for_delivery_at": delivery.out_for_delivery_at.isoformat() if delivery.out_for_delivery_at else None,
            "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
            "pickup_notes": delivery.pickup_notes,
            "delivery_notes": delivery.delivery_notes,
            "delivery_otp": delivery.delivery_otp
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")

@app.route('/rider/delivery/<int:delivery_id>/location', methods=['PUT'])
@require_role('rider')
def update_rider_live_location(delivery_id):
    """Update live location during a delivery"""
    data = request.json
    lat = data.get('latitude')
    lon = data.get('longitude')
    
    delivery = DeliveryLog.query.get(delivery_id)
    if not delivery:
         return jsonify({"error": "Delivery not found"}), 404
         
    try:
        delivery.current_latitude = lat
        delivery.current_longitude = lon
        delivery.last_location_update = datetime.utcnow()
        db.session.commit()
        return jsonify({"message": "Location updated"}), 200
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# =====================================================
# ADMIN NOTIFICATIONS
# =====================================================
@app.route('/admin/notifications', methods=['GET'])
@require_role('admin')
def get_admin_notifications():
    """Get all notifications for admin"""
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    query = Notification.query.filter_by(user_type='admin')
    
    if unread_only:
        query = query.filter_by(is_read=False)
    
    notifs = query.order_by(Notification.created_at.desc()).limit(50).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifs]), 200

@app.route('/admin/notifications/<int:notif_id>/read', methods=['POST'])
@require_role('admin')
def mark_admin_notification_read(notif_id):
    """Mark a specific admin notification as read"""
    notif = Notification.query.get(notif_id)
    if not notif:
        return jsonify({"error": "Notification not found"}), 404
    notif.is_read = True
    db.session.commit()
    return jsonify({"message": "Notification marked as read"}), 200


# =====================================================
# CUSTOMER NOTIFICATIONS
# =====================================================
@app.route('/customer/notifications/<int:customer_id>', methods=['GET'])
@require_self_or_role('customer_id', 'admin')
def get_customer_notifications(customer_id):
    """Get all notifications for a specific customer"""
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    query = Notification.query.filter_by(user_id=customer_id, user_type='customer')
    
    if unread_only:
        query = query.filter_by(is_read=False)
    
    notifs = query.order_by(Notification.created_at.desc()).limit(50).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifs]), 200

@app.route('/customer/notifications/<int:notif_id>/read', methods=['POST'])
@require_role('customer')
def mark_customer_notification_read(notif_id):
    """Mark a specific customer notification as read"""
    notif = Notification.query.get(notif_id)
    if not notif:
        return jsonify({"error": "Notification not found"}), 404
    notif.is_read = True
    db.session.commit()
    return jsonify({"message": "Notification marked as read"}), 200


# =====================================================
# ORDER TRACKING
# =====================================================
@app.route('/orders/<int:order_id>/tracking', methods=['GET'])
@require_auth
def get_order_tracking(order_id):
    """Get complete order tracking history for real-time progress display"""
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    
    # Get all status history records
    history = OrderStatusHistory.query.filter_by(order_id=order_id).order_by(OrderStatusHistory.created_at.asc()).all()
    
    # Define the complete tracking stages
    TRACKING_STAGES = [
        {'id': 'pending_admin_review', 'label': 'Order Received', 'icon': 'clipboard-check'},
        {'id': 'quotation_sent_to_customer', 'label': 'Quotation Sent', 'icon': 'file-text'},
        {'id': 'sample_requested', 'label': 'Sample Stage', 'icon': 'package'},
        {'id': 'awaiting_advance_payment', 'label': 'Payment Received', 'icon': 'credit-card'},
        {'id': 'assigned', 'label': 'Vendor Assigned', 'icon': 'user-check'},
        {'id': 'accepted_by_vendor', 'label': 'Accepted by Vendor', 'icon': 'check-circle'},
        {'id': 'material_prep', 'label': 'Material Preparation', 'icon': 'scissors'},
        {'id': 'printing', 'label': 'Printing', 'icon': 'printer'},
        {'id': 'printing_completed', 'label': 'Printing Completed', 'icon': 'check-square'},
        {'id': 'quality_check', 'label': 'Quality Check', 'icon': 'search'},
        {'id': 'packed_ready', 'label': 'Packed & Ready', 'icon': 'package'},
        {'id': 'reached_vendor', 'label': 'Rider Arrived', 'icon': 'map-pin'},
        {'id': 'picked_up', 'label': 'Picked Up', 'icon': 'package-check'},
        {'id': 'out_for_delivery', 'label': 'Out for Delivery', 'icon': 'truck'},
        {'id': 'delivered', 'label': 'Delivered', 'icon': 'home'}
    ]
    
    # Build history timeline
    history_timeline = [{
        'status': h.status,
        'status_label': h.status_label,
        'changed_by_type': h.changed_by_type,
        'changed_by_id': h.changed_by_id,
        'notes': h.notes,
        'timestamp': h.created_at.isoformat()
    } for h in history]
    
    # Calculate current stage index
    current_status = order.status
    current_index = -1
    for i, stage in enumerate(TRACKING_STAGES):
        if stage['id'] == current_status:
            current_index = i
            break
    
    # If status not found in stages, try to find closest match
    if current_index == -1:
        status_aliases = {
            'pending': 0,
            'in_production': 7,
            'completed_with_penalty': 12
        }
        current_index = status_aliases.get(current_status, 0)
    
    return jsonify({
        'order_id': order.id,
        'current_status': current_status,
        'current_stage_index': current_index,
        'sample_cost': order.sample_cost or 0,
        'stages': TRACKING_STAGES,
        'history': history_timeline,
        'created_at': order.created_at.isoformat() if order.created_at else None
    }), 200


# ==========================================
# VENDOR RIDER TRACKING ENDPOINT
# ==========================================

@app.route('/vendor/track-delivery/<int:delivery_id>', methods=['GET'])
@require_role('vendor', 'admin', 'customer')
def vendor_track_delivery(delivery_id):
    """Allow vendor to track assigned rider's live location during pickup"""
    try:
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        # Get order and rider details
        order = Order.query.get(delivery.order_id)
        rider = Rider.query.get(delivery.assigned_rider_id)
        
        # Get vendor details (assuming vendor_id can be derived from order)
        vendor_id = order.selected_vendor_id if order else None
        vendor = Vendor.query.get(vendor_id) if vendor_id else None
        
        return jsonify({
            "delivery_id": delivery.id,
            "order_id": delivery.order_id,
            "status": delivery.status,
            "rider": {
                "id": rider.id if rider else None,
                "name": rider.name if rider else None,
                "phone": rider.phone if rider else None,
                "vehicle_type": rider.vehicle_type if rider else None
            },
            "rider_location": {
                "latitude": delivery.current_latitude,
                "longitude": delivery.current_longitude,
                "last_update": delivery.last_location_update.isoformat() if delivery.last_location_update else None
            } if delivery.current_latitude and delivery.current_longitude else None,
            "vendor_location": {
                "latitude": vendor.latitude if vendor else None,
                "longitude": vendor.longitude if vendor else None,
                "address": vendor.address if vendor else None
            },
            "product": {
                "type": order.category if order else None,
                "quantity": order.quantity if order else None
            },
            "assigned_at": delivery.assigned_at.isoformat() if delivery.assigned_at else None,
            "reached_vendor_at": delivery.reached_vendor_at.isoformat() if delivery.reached_vendor_at else None
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


# ==========================================
# PROXIMITY-BASED RIDER ASSIGNMENT SYSTEM
# ==========================================

def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    Returns distance in kilometers
    """
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Radius of earth in kilometers
    r = 6371
    
    return c * r

def find_nearest_riders(vendor_lat, vendor_lon, max_distance_km=10, limit=5):
    """
    Find nearest available riders within max_distance_km radius
    Returns list of (rider, distance) tuples sorted by distance
    """
    # Get all online and verified riders
    riders = Rider.query.filter(
        Rider.is_online == True,
        Rider.verification_status == 'approved',
        Rider.latitude.isnot(None),
        Rider.longitude.isnot(None)
    ).all()
    
    rider_distances = []
    
    for rider in riders:
        distance = haversine_distance(
            vendor_lat, vendor_lon,
            rider.latitude, rider.longitude
        )
        
        # Only include riders within max distance
        if distance <= max_distance_km:
            rider_distances.append((rider, distance))
    
    # Sort by distance (nearest first)
    rider_distances.sort(key=lambda x: x[1])
    
    # Return top N nearest riders
    return rider_distances[:limit]

def assign_nearest_rider_to_order(order_id, vendor_id, max_search_radius_km=10):
    """
    Assign the nearest available rider to an order for pickup from vendor
    
    Args:
        order_id: ID of the order to be delivered
        vendor_id: ID of the vendor where pickup should happen
        max_search_radius_km: Maximum search radius for riders (default 10km)
    
    Returns:
        dict with assignment result
    """
    try:
        # Get vendor location
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return {
                'success': False,
                'error': 'Vendor not found'
            }
        
        if not vendor.latitude or not vendor.longitude:
            return {
                'success': False,
                'error': 'Vendor location not set. Please update vendor profile with GPS coordinates.'
            }
        
        # Get order details
        order = Order.query.get(order_id)
        if not order:
            return {
                'success': False,
                'error': 'Order not found'
            }
        
        # Find nearest available riders
        nearest_riders = find_nearest_riders(
            vendor.latitude,
            vendor.longitude,
            max_distance_km=max_search_radius_km,
            limit=5
        )
        
        if not nearest_riders:
            return {
                'success': False,
                'error': f'No available riders found within {max_search_radius_km}km radius',
                'suggestion': 'Try increasing search radius or wait for riders to come online'
            }
        
        # Assign to the nearest rider
        rider, distance = nearest_riders[0]
        
        # Check if delivery log already exists
        existing_log = DeliveryLog.query.filter_by(order_id=order_id).first()
        
        if existing_log:
            # Update existing delivery log
            existing_log.assigned_rider_id = rider.id
            existing_log.vendor_address = f"{vendor.address}, {vendor.city}, {vendor.state} - {vendor.pincode}"
            existing_log.vendor_contact = vendor.phone
            existing_log.customer_address = f"{order.address_line1}, {order.city}, {order.state} - {order.pincode}"
            existing_log.status = 'assigned'
            existing_log.assigned_at = datetime.utcnow()
            
            db.session.commit()
            
            return {
                'success': True,
                'message': 'Delivery assignment updated',
                'rider': {
                    'id': rider.id,
                    'name': rider.name,
                    'phone': rider.phone,
                    'vehicle_type': rider.vehicle_type,
                    'distance_km': round(distance, 2)
                },
                'vendor': {
                    'name': vendor.business_name,
                    'address': vendor.address,
                    'city': vendor.city
                },
                'alternatives': [
                    {
                        'rider_id': r.id,
                        'name': r.name,
                        'distance_km': round(d, 2)
                    }
                    for r, d in nearest_riders[1:4]  # Show next 3 alternatives
                ]
            }
        else:
            # Create new delivery log
            delivery_log = DeliveryLog(
                order_id=order_id,
                assigned_rider_id=rider.id,
                vendor_address=f"{vendor.address}, {vendor.city}, {vendor.state} - {vendor.pincode}",
                vendor_contact=vendor.phone,
                customer_address=f"{order.address_line1}, {order.city}, {order.state} - {order.pincode}",
                status='assigned',
                assigned_at=datetime.utcnow()
            )
            
            db.session.add(delivery_log)
            db.session.commit()
            
            return {
                'success': True,
                'message': 'Rider assigned successfully',
                'delivery_log_id': delivery_log.id,
                'rider': {
                    'id': rider.id,
                    'name': rider.name,
                    'phone': rider.phone,
                    'vehicle_type': rider.vehicle_type,
                    'distance_km': round(distance, 2)
                },
                'vendor': {
                    'name': vendor.business_name,
                    'address': vendor.address,
                    'city': vendor.city
                },
                'alternatives': [
                    {
                        'rider_id': r.id,
                        'name': r.name,
                        'distance_km': round(d, 2)
                    }
                    for r, d in nearest_riders[1:4]  # Show next 3 alternatives
                ]
            }
            
    except Exception as e:
        db.session.rollback()
        log_error(e, {"function": "admin_find_nearby_riders"})
        return {
            'success': False,
            'error': get_error_message(e, "Failed to find nearby riders. Please try again.")
        }

def get_rider_delivery_stats(rider_id):
    """Get delivery statistics for a rider"""
    logs = DeliveryLog.query.filter_by(assigned_rider_id=rider_id).all()
    
    total_deliveries = len(logs)
    completed = sum(1 for log in logs if log.status == 'delivered')
    in_progress = sum(1 for log in logs if log.status in ['assigned', 'reached_vendor', 'picked_up', 'out_for_delivery'])
    failed = sum(1 for log in logs if log.status in ['failed', 'returned'])
    
    return {
        'total_deliveries': total_deliveries,
        'completed': completed,
        'in_progress': in_progress,
        'failed': failed,
        'success_rate': round((completed / total_deliveries * 100), 2) if total_deliveries > 0 else 0
    }

@app.route('/rider/update-location', methods=['POST'])
@app.route('/rider/update-location', methods=['POST'], subdomain='rider')
@require_role('rider')
def rider_update_location():
    """Update rider's current GPS location for proximity matching"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        rider_id = data.get('rider_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not rider_id:
            return jsonify({"error": "Rider ID required"}), 400
        
        if latitude is None or longitude is None:
            return jsonify({"error": "GPS coordinates required"}), 400
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Update rider location
        rider.latitude = float(latitude)
        rider.longitude = float(longitude)
        rider.last_online_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "message": "Location updated successfully",
            "rider_id": rider_id,
            "latitude": latitude,
            "longitude": longitude,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/assign-rider', methods=['POST'])
@require_role('admin')
def admin_assign_rider_proximity():
    """
    Assign nearest available rider to an order based on vendor location
    Uses proximity-based matching algorithm
    """
    try:
        data = request.json
        order_id = data.get('order_id')
        vendor_id = data.get('vendor_id')
        max_radius_km = data.get('max_radius_km', 10)  # Default 10km radius
        
        if not order_id or not vendor_id:
            return jsonify({
                "error": "order_id and vendor_id are required"
            }), 400
        
        # Call the proximity assignment function
        result = assign_nearest_rider_to_order(
            order_id=order_id,
            vendor_id=vendor_id,
            max_search_radius_km=max_radius_km
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/admin/find-nearby-riders', methods=['POST'])
@require_role('admin')
def admin_find_nearby_riders():
    """
    Find all available riders near a vendor location
    Returns sorted list by distance for manual selection
    """
    try:
        data = request.json
        vendor_id = data.get('vendor_id')
        max_radius_km = data.get('max_radius_km', 10)
        limit = data.get('limit', 10)
        
        if not vendor_id:
            return jsonify({"error": "vendor_id is required"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if not vendor.latitude or not vendor.longitude:
            return jsonify({
                "error": "Vendor location not set",
                "message": "Please update vendor profile with GPS coordinates"
            }), 400
        
        # Find nearby riders
        nearby_riders = find_nearest_riders(
            vendor.latitude,
            vendor.longitude,
            max_distance_km=max_radius_km,
            limit=limit
        )
        
        if not nearby_riders:
            return jsonify({
                "message": f"No riders found within {max_radius_km}km",
                "riders": [],
                "vendor": {
                    "id": vendor.id,
                    "name": vendor.business_name,
                    "latitude": vendor.latitude,
                    "longitude": vendor.longitude
                }
            }), 200
        
        # Format response
        riders_list = []
        for rider, distance in nearby_riders:
            stats = get_rider_delivery_stats(rider.id)
            riders_list.append({
                "rider_id": rider.id,
                "name": rider.name,
                "phone": rider.phone,
                "vehicle_type": rider.vehicle_type,
                "distance_km": round(distance, 2),
                "is_online": rider.is_online,
                "stats": stats,
                "current_location": {
                    "latitude": rider.latitude,
                    "longitude": rider.longitude
                }
            })
        
        return jsonify({
            "message": f"Found {len(riders_list)} riders within {max_radius_km}km",
            "riders": riders_list,
            "vendor": {
                "id": vendor.id,
                "name": vendor.business_name,
                "address": vendor.address,
                "city": vendor.city,
                "latitude": vendor.latitude,
                "longitude": vendor.longitude
            }
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")


@app.route('/rider/stats/<int:rider_id>', methods=['GET'])
@require_self_or_role('rider_id', 'admin')
def get_rider_stats(rider_id):
    """Get delivery statistics for a specific rider"""
    try:
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        stats = get_rider_delivery_stats(rider_id)
        
        return jsonify({
            "rider_id": rider_id,
            "name": rider.name,
            "stats": stats
        }), 200
        
    except Exception as e:
        return handle_exception(e, {"endpoint": request.path, "method": request.method}, "An error occurred while processing your request.")



# Public Health Check Endpoint (for load balancers and monitoring)
@app.route('/health', methods=['GET'])
@app.route('/status', methods=['GET'])
def health_check():
    """
    Public health check endpoint for load balancers and monitoring systems
    Returns basic application status without authentication
    """
    try:
        health_status = {
            "status": "healthy",
            "service": "Impromptu Indian API",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "environment": Config.ENV
        }
        
        # Basic database connectivity check (lightweight)
        try:
            engine = db.get_engine()
            with engine.connect() as conn:
                conn.execute("SELECT 1")
            health_status["database"] = "connected"
        except Exception as db_error:
            health_status["status"] = "degraded"
            health_status["database"] = "disconnected"
            health_status["database_error"] = str(db_error)
            return jsonify(health_status), 503
        
        return jsonify(health_status), 200
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": "Health check failed",
            "timestamp": datetime.utcnow().isoformat()
        }), 503

# Detailed Database Health Check Endpoint (Admin only)
@app.route('/api/health/database', methods=['GET'])
@require_role('admin')  # Only admins can check detailed database health
def database_health_check():
    """Check database connection health and pool status"""
    try:
        # Check main database
        engine = db.get_engine()
        is_healthy, message = check_database_health(engine)
        pool_status = get_pool_status(engine)
        
        return jsonify({
            "status": "healthy" if is_healthy else "unhealthy",
            "message": message,
            "pool_status": pool_status,
            "timestamp": datetime.utcnow().isoformat()
        }), 200 if is_healthy else 503
        
    except Exception as e:
        return handle_exception(e, {"endpoint": "/api/health/database"}, "Database health check failed")

if __name__ == '__main__':
    # Production should use gunicorn or similar WSGI server
    # This is only for local development
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)
