"""
Logging Configuration
Provides structured logging with rotation for production use
Includes optional Sentry integration for error tracking
"""
import logging
import logging.handlers
import os
from datetime import datetime
from config import Config

# Optional Sentry integration for error tracking
SENTRY_DSN = os.environ.get('SENTRY_DSN')
if SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        
        # Configure Sentry
        sentry_logging = LoggingIntegration(
            level=logging.INFO,        # Capture info and above as breadcrumbs
            event_level=logging.ERROR   # Send errors and above as events
        )
        
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[
                FlaskIntegration(),
                sentry_logging
            ],
            traces_sample_rate=1.0 if Config.ENV == 'development' else 0.1,  # 100% in dev, 10% in prod
            environment=Config.ENV,
            send_default_pii=False  # Don't send personally identifiable information
        )
        SENTRY_ENABLED = True
        # Create a temporary logger for initialization messages (before main loggers are set up)
        _init_logger = logging.getLogger('sentry_init')
        _init_logger.setLevel(logging.WARNING)
        if not _init_logger.handlers:
            _init_logger.addHandler(logging.StreamHandler())
        _init_logger.info("Sentry error tracking initialized successfully")
    except ImportError:
        # Sentry SDK not installed, continue without it
        SENTRY_ENABLED = False
        _init_logger = logging.getLogger('sentry_init')
        _init_logger.setLevel(logging.WARNING)
        if not _init_logger.handlers:
            _init_logger.addHandler(logging.StreamHandler())
        _init_logger.warning("SENTRY_DSN is set but sentry-sdk is not installed. Install with: pip install sentry-sdk[flask]")
    except Exception as e:
        SENTRY_ENABLED = False
        _init_logger = logging.getLogger('sentry_init')
        _init_logger.setLevel(logging.WARNING)
        if not _init_logger.handlers:
            _init_logger.addHandler(logging.StreamHandler())
        _init_logger.warning(f"Failed to initialize Sentry: {e}")
else:
    SENTRY_ENABLED = False

# Create logs directory if it doesn't exist
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Log file paths
APP_LOG_FILE = os.path.join(LOG_DIR, 'app.log')
ERROR_LOG_FILE = os.path.join(LOG_DIR, 'error.log')
ACCESS_LOG_FILE = os.path.join(LOG_DIR, 'access.log')
AUTH_LOG_FILE = os.path.join(LOG_DIR, 'auth.log')

# Log format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Log level based on environment
LOG_LEVEL = logging.DEBUG if Config.ENV == 'development' else logging.INFO


def setup_logger(name, log_file, level=LOG_LEVEL, max_bytes=10*1024*1024, backup_count=30):
    """
    Set up a logger with file rotation
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        max_bytes: Maximum size of log file before rotation (default 10MB)
        backup_count: Number of backup files to keep (default 30 days)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    
    # Console handler (for development)
    if Config.ENV == 'development':
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(console_handler)
    
    logger.addHandler(file_handler)
    
    return logger


# Application Logger (general application logs)
app_logger = setup_logger('app', APP_LOG_FILE, LOG_LEVEL)

# Error Logger (errors and exceptions)
error_logger = setup_logger('error', ERROR_LOG_FILE, logging.ERROR)

# Access Logger (API access logs)
access_logger = setup_logger('access', ACCESS_LOG_FILE, logging.INFO)

# Authentication Logger (login attempts, auth events)
auth_logger = setup_logger('auth', AUTH_LOG_FILE, logging.INFO)


def log_request(request, response=None, duration=None):
    """
    Log API request/response
    
    Args:
        request: Flask request object
        response: Flask response object (optional)
        duration: Request duration in seconds (optional)
    """
    log_data = {
        'method': request.method,
        'path': request.path,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
    }
    
    if response:
        log_data['status_code'] = response.status_code
    
    if duration:
        log_data['duration_ms'] = round(duration * 1000, 2)
    
    # Log authenticated requests with user info
    try:
        from auth import get_current_user
        user = get_current_user()
        if user:
            log_data['user_id'] = user.get('user_id')
            log_data['role'] = user.get('role')
    except Exception:
        pass
    
    access_logger.info(f"Request: {log_data}")


def log_auth_event(event_type, success, identifier=None, user_id=None, role=None, ip_address=None, error=None):
    """
    Log authentication events
    
    Args:
        event_type: Type of event (login, logout, register, token_refresh, etc.)
        success: Whether the operation was successful
        identifier: Username/email/phone used
        user_id: User ID if authenticated
        role: User role if authenticated
        ip_address: Client IP address
        error: Error message if failed
    """
    log_data = {
        'event_type': event_type,
        'success': success,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    if identifier:
        # Mask sensitive identifier (show only first 3 chars)
        masked_id = identifier[:3] + '*' * (len(identifier) - 3) if len(identifier) > 3 else '***'
        log_data['identifier'] = masked_id
    
    if user_id:
        log_data['user_id'] = user_id
    
    if role:
        log_data['role'] = role
    
    if ip_address:
        log_data['ip_address'] = ip_address
    
    if error:
        log_data['error'] = str(error)
    
    if success:
        auth_logger.info(f"Auth Event: {log_data}")
    else:
        auth_logger.warning(f"Auth Event Failed: {log_data}")


def log_error_with_context(error, context=None, level=logging.ERROR):
    """
    Log error with context information
    
    Args:
        error: Exception object or error message
        context: Additional context dictionary
        level: Logging level
    """
    import traceback
    
    log_data = {
        'error_type': type(error).__name__ if hasattr(error, '__class__') else 'Unknown',
        'error_message': str(error),
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    if context:
        log_data['context'] = context
    
    # Add traceback for exceptions
    if hasattr(error, '__traceback__'):
        log_data['traceback'] = traceback.format_exc()
    
    error_logger.log(level, f"Error: {log_data}")
    
    # Send to Sentry if enabled
    if SENTRY_ENABLED and isinstance(error, Exception):
        try:
            import sentry_sdk
            with sentry_sdk.push_scope() as scope:
                if context:
                    for key, value in context.items():
                        scope.set_context(key, value)
                scope.set_tag("error_type", log_data['error_type'])
                sentry_sdk.capture_exception(error)
        except Exception:
            # Fail silently if Sentry capture fails
            pass


def log_info(message, context=None):
    """Log informational message"""
    if context:
        app_logger.info(f"{message} | Context: {context}")
    else:
        app_logger.info(message)


def log_warning(message, context=None):
    """Log warning message"""
    if context:
        app_logger.warning(f"{message} | Context: {context}")
    else:
        app_logger.warning(message)


def log_debug(message, context=None):
    """Log debug message"""
    if context:
        app_logger.debug(f"{message} | Context: {context}")
    else:
        app_logger.debug(message)

