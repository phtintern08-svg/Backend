import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Environment Configuration - PRODUCTION ONLY
    ENV = os.environ.get('ENV', 'production')  # Default to production
    DEBUG = False  # Always False in production
    TESTING = False
    
    # Secret key for session management and security
    # Required - no default fallback
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable is required")
    
    # Domain Configuration - PRODUCTION ONLY
    BASE_DOMAIN = os.environ.get('BASE_DOMAIN', 'impromptuindian.com')
    APP_SUBDOMAIN = os.environ.get('APP_SUBDOMAIN', 'apparels')
    VENDOR_SUBDOMAIN = os.environ.get('VENDOR_SUBDOMAIN', 'vendor')
    RIDER_SUBDOMAIN = os.environ.get('RIDER_SUBDOMAIN', 'rider')
    
    # Server Configuration - PRODUCTION ONLY
    SERVER_NAME = BASE_DOMAIN
    
    # Database Credentials (from environment variables - required in production)
    MYSQL_USER = os.environ.get('DB_USER')
    MYSQL_PASSWORD = os.environ.get('DB_PASSWORD')
    MYSQL_HOST = os.environ.get('DB_HOST')
    MYSQL_PORT = int(os.environ.get('DB_PORT', 3306))
    
    # Validate database credentials - REQUIRED
    if not MYSQL_USER or not MYSQL_PASSWORD or not MYSQL_HOST:
        raise ValueError("DB_USER, DB_PASSWORD, and DB_HOST environment variables are required")
    
    # Database Names (from environment variables - required in production)
    DB_NAME_ADMIN = os.environ.get('DB_NAME_ADMIN')
    DB_NAME_CUSTOMER = os.environ.get('DB_NAME_CUSTOMER')
    DB_NAME_VENDOR = os.environ.get('DB_NAME_VENDOR')
    DB_NAME_RIDER = os.environ.get('DB_NAME_RIDER')
    DB_NAME_SUPPORT = os.environ.get('DB_NAME_SUPPORT')
    
    # Validate database names in production
    if ENV == 'production':
        if not DB_NAME_ADMIN or not DB_NAME_CUSTOMER or not DB_NAME_VENDOR or not DB_NAME_RIDER or not DB_NAME_SUPPORT:
            raise ValueError("All database name environment variables (DB_NAME_ADMIN, DB_NAME_CUSTOMER, DB_NAME_VENDOR, DB_NAME_RIDER, DB_NAME_SUPPORT) are required in production")
    
    # Primary database (Admin schema - default) - PRODUCTION ONLY
    # All database names are required from environment variables
    MYSQL_DB = DB_NAME_ADMIN
    
    # Main SQLAlchemy Database URI (Admin schema as default)
    if MYSQL_USER and MYSQL_PASSWORD and MYSQL_HOST and MYSQL_DB:
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
        
        # Binds for different schemas (each is a separate MySQL database) - PRODUCTION ONLY
        # All database names are required from environment variables
        admin_db = DB_NAME_ADMIN
        customer_db = DB_NAME_CUSTOMER
        vendor_db = DB_NAME_VENDOR
        rider_db = DB_NAME_RIDER
        support_db = DB_NAME_SUPPORT
        
        if admin_db and customer_db and vendor_db and rider_db and support_db:
            SQLALCHEMY_BINDS = {
                'admin': f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{admin_db}",
                'customer': f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{customer_db}",
                'vendor': f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{vendor_db}",
                'rider': f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{rider_db}",
                'support': f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{support_db}",
            }
        else:
            SQLALCHEMY_BINDS = {}
    else:
        # PRODUCTION ONLY - All credentials are required
        SQLALCHEMY_DATABASE_URI = None
        SQLALCHEMY_BINDS = {}
    
    # Disable modification tracking to save resources
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database Connection Pooling Configuration
    # Pool size based on expected load (adjust based on server capacity)
    DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 10))  # Default 10 connections
    DB_MAX_OVERFLOW = int(os.environ.get('DB_MAX_OVERFLOW', 20))  # Max 20 additional connections
    DB_POOL_TIMEOUT = int(os.environ.get('DB_POOL_TIMEOUT', 30))  # 30 seconds timeout
    DB_POOL_RECYCLE = int(os.environ.get('DB_POOL_RECYCLE', 3600))  # Recycle after 1 hour
    DB_CONNECT_TIMEOUT = int(os.environ.get('DB_CONNECT_TIMEOUT', 10))  # 10 seconds connection timeout
    
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before using
        'pool_recycle': DB_POOL_RECYCLE,  # Recycle connections after this time
        'pool_size': DB_POOL_SIZE,  # Number of connections to maintain
        'max_overflow': DB_MAX_OVERFLOW,  # Max additional connections beyond pool_size
        'pool_timeout': DB_POOL_TIMEOUT,  # Timeout when getting connection from pool
        'connect_args': {
            'connect_timeout': DB_CONNECT_TIMEOUT,  # Connection timeout
            'read_timeout': 30,  # Read timeout
            'write_timeout': 30,  # Write timeout
            'charset': 'utf8mb4',
            'autocommit': False,  # Use transactions
        }
    }
    
    # Session Configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    
    # Session Timeout Configuration (in seconds)
    # Default: 30 minutes (1800 seconds) - can be overridden via environment variable
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 1800))  # 30 minutes
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_TIMEOUT)
    
    # Session Cookie Max Age (should match PERMANENT_SESSION_LIFETIME)
    SESSION_COOKIE_MAX_AGE = SESSION_TIMEOUT
    
    # CSRF Protection Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    WTF_CSRF_SSL_STRICT = ENV == 'production'  # Only enforce SSL in production
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    # Content Security Policy (CSP) Configuration
    CSP_DEFAULT_SRC = "'self'"
    CSP_SCRIPT_SRC = "'self' 'unsafe-inline' 'unsafe-eval'"  # Adjust based on your needs
    CSP_STYLE_SRC = "'self' 'unsafe-inline'"
    CSP_IMG_SRC = "'self' data: https:"
    CSP_FONT_SRC = "'self' data:"
    CSP_CONNECT_SRC = "'self'"
    CSP_FRAME_ANCESTORS = "'none'"
    
    # CORS Configuration
    ALLOWED_ORIGINS = os.environ.get(
        'ALLOWED_ORIGINS',
        'http://localhost:5000,http://127.0.0.1:5000'
    ).split(',')
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'}
    
    # MSG91 Configuration - DISABLED
    # Get credentials from https://msg91.com
    # Authkey is required for MSG91 SMS API
    # MSG91_AUTHKEY = os.environ.get('MSG91_AUTHKEY')
    # Widget ID and Token Auth for MSG91 OTP widget (required from .env)
    # MSG91_WIDGET_ID = os.environ.get('MSG91_WIDGET_ID')
    # MSG91_TOKEN_AUTH = os.environ.get('MSG91_TOKEN_AUTH')
    # Sender ID (6 characters, alphanumeric) - required for SMS sending
    # MSG91_SENDER_ID = os.environ.get('MSG91_SENDER_ID', 'IMPRTU')
    # MSG91 Route (1=Promotional, 4=Transactional) - defaults to 4 for OTP
    # MSG91_ROUTE = os.environ.get('MSG91_ROUTE', '4')
    # DLT Template ID (if you have registered template with DLT)
    # MSG91_DLT_TE_ID = os.environ.get('MSG91_DLT_TE_ID', '').strip()
    
    # Placeholder values to prevent errors
    MSG91_AUTHKEY = None
    MSG91_WIDGET_ID = None
    MSG91_TOKEN_AUTH = None
    MSG91_SENDER_ID = None
    MSG91_ROUTE = '4'
    MSG91_DLT_TE_ID = ''
    
    # Production Security Settings
    if ENV == 'production':
        # Force HTTPS
        PREFERRED_URL_SCHEME = 'https'
        # Strict transport security
        SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year
