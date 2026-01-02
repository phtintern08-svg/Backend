"""
Environment Variable Validation
Validates all required environment variables on application startup
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ENV = os.environ.get('ENV', 'development')
REQUIRED_VARS = {
    'production': [
        'SECRET_KEY',
        'DB_USER',
        'DB_PASSWORD',
        'DB_HOST',
        'DB_NAME_ADMIN',
        'DB_NAME_CUSTOMER',
        'DB_NAME_VENDOR',
        'DB_NAME_RIDER',
        'DB_NAME_SUPPORT',
        'MAIL_USERNAME',
        'MAIL_PASSWORD',
        'MAPPLS_API_KEY',
    ],
    'development': [
        # Development has fewer requirements
        'SECRET_KEY',  # Optional but recommended
    ]
}

OPTIONAL_VARS = [
    'BASE_DOMAIN',
    'APP_SUBDOMAIN',
    'VENDOR_SUBDOMAIN',
    'RIDER_SUBDOMAIN',
    'DB_PORT',
    'DB_POOL_SIZE',
    'DB_MAX_OVERFLOW',
    'DB_POOL_TIMEOUT',
    'DB_POOL_RECYCLE',
    'DB_CONNECT_TIMEOUT',
    'MAIL_SERVER',
    'MAIL_PORT',
    'MAIL_USE_TLS',
    'MAIL_DEFAULT_SENDER',
    'ALLOWED_ORIGINS',
    'SESSION_COOKIE_SECURE',
    'SESSION_COOKIE_HTTPONLY',
    'SESSION_COOKIE_SAMESITE',
    'INITIAL_ADMIN_USERNAME',
    'INITIAL_ADMIN_PASSWORD',
    'DEFAULT_ADMIN_USERNAME',
    'DEFAULT_ADMIN_PASSWORD',
    'SENTRY_DSN',
    'MSG91_AUTHKEY',  # Optional - for MSG91 SMS API
    'MSG91_SENDER_ID',  # Optional - for MSG91 SMS API (defaults to IMPRTU)
    'MSG91_ROUTE',  # Optional - MSG91 route (1=Promotional, 4=Transactional, default: 4)
    'MSG91_DLT_TE_ID',  # Optional - DLT Template ID for MSG91
    'MSG91_WIDGET_ID',  # Optional - for MSG91 OTP widget
    'MSG91_TOKEN_AUTH',  # Optional - for MSG91 OTP widget
]


def validate_environment():
    """
    Validate all required environment variables
    
    Returns:
        Tuple of (is_valid, missing_vars, warnings)
    """
    missing_vars = []
    warnings = []
    
    # Check required variables for current environment
    required = REQUIRED_VARS.get(ENV, [])
    
    for var in required:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    # Check for recommended variables
    if ENV == 'production':
        if not os.environ.get('BASE_DOMAIN'):
            warnings.append("BASE_DOMAIN not set - using default")
        
        if not os.environ.get('ALLOWED_ORIGINS'):
            warnings.append("ALLOWED_ORIGINS not set - CORS may not work correctly")
        
        # Check for SMS provider configuration
        has_msg91_api = os.environ.get('MSG91_AUTHKEY')
        has_msg91_widget = os.environ.get('MSG91_WIDGET_ID') and os.environ.get('MSG91_TOKEN_AUTH')
        
        if not has_msg91_api:
            warnings.append("MSG91_AUTHKEY not configured. Phone OTP SMS will not be sent (OTP will still be generated).")
        if not has_msg91_widget:
            warnings.append("MSG91_WIDGET_ID and MSG91_TOKEN_AUTH not configured. OTP widget will not work.")
    
    # Check for development-only variables in production
    if ENV == 'production':
        if os.environ.get('DEFAULT_ADMIN_USERNAME') or os.environ.get('DEFAULT_ADMIN_PASSWORD'):
            warnings.append("DEFAULT_ADMIN_* variables should not be used in production")
    
    is_valid = len(missing_vars) == 0
    
    return is_valid, missing_vars, warnings


def print_validation_results():
    """Print validation results to console"""
    is_valid, missing_vars, warnings = validate_environment()
    
    print(f"\n{'='*60}")
    print(f"Environment Variable Validation - {ENV.upper()}")
    print(f"{'='*60}\n")
    
    if is_valid:
        print("✓ All required environment variables are set\n")
    else:
        print("✗ Missing required environment variables:\n")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables in your .env file or environment")
        print("See .env.example for reference\n")
    
    if warnings:
        print("⚠ Warnings:\n")
        for warning in warnings:
            print(f"  - {warning}")
        print()
    
    print(f"{'='*60}\n")
    
    return is_valid


if __name__ == '__main__':
    is_valid = print_validation_results()
    if not is_valid:
        sys.exit(1)

