"""
Database Connection Management
Provides connection retry logic and health monitoring
"""
import time
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import Pool
from sqlalchemy.exc import DisconnectionError, OperationalError
from config import Config
from logger_config import log_error_with_context, log_warning, log_info

logger = logging.getLogger(__name__)


def create_engine_with_retry(database_uri: str, engine_options: dict, max_retries: int = 3, retry_delay: int = 2):
    """
    Create database engine with retry logic
    
    Args:
        database_uri: Database connection URI
        engine_options: SQLAlchemy engine options
        max_retries: Maximum number of connection retry attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        SQLAlchemy Engine object
    """
    for attempt in range(max_retries):
        try:
            engine = create_engine(database_uri, **engine_options)
            
            # Test connection
            with engine.connect() as conn:
                conn.execute("SELECT 1")
            
            log_info(f"Database connection established successfully (attempt {attempt + 1})")
            return engine
            
        except (DisconnectionError, OperationalError) as e:
            if attempt < max_retries - 1:
                log_warning(f"Database connection failed (attempt {attempt + 1}/{max_retries}): {str(e)}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                log_error_with_context(e, {"database_uri": database_uri.split('@')[1] if '@' in database_uri else "hidden"})
                raise
        except Exception as e:
            log_error_with_context(e, {"database_uri": database_uri.split('@')[1] if '@' in database_uri else "hidden"})
            raise
    
    raise ConnectionError(f"Failed to establish database connection after {max_retries} attempts")


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Set connection-level settings (for MySQL)"""
    # This is called for each new connection
    try:
        # Set session variables for MySQL
        dbapi_conn.execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'")
        dbapi_conn.execute("SET SESSION time_zone='+00:00'")  # UTC timezone
    except Exception:
        # Ignore errors (might not be MySQL)
        pass


@event.listens_for(Pool, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Called when a new connection is established"""
    log_info("New database connection established")


# REMOVED: checkout handler - pool_pre_ping handles connection validation automatically
# Having a custom checkout handler can interfere with connection pool management


def check_database_health(engine):
    """
    Check database connection health
    
    Args:
        engine: SQLAlchemy Engine object
        
    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        with engine.connect() as conn:
            result = conn.execute("SELECT 1 as health_check")
            row = result.fetchone()
            if row and row[0] == 1:
                return True, "Database connection is healthy"
            else:
                return False, "Database health check failed"
    except Exception as e:
        return False, f"Database health check error: {str(e)}"


def get_pool_status(engine):
    """
    Get connection pool status
    
    Args:
        engine: SQLAlchemy Engine object
        
    Returns:
        Dictionary with pool status information
    """
    pool = engine.pool
    return {
        'size': pool.size(),
        'checked_in': pool.checkedin(),
        'checked_out': pool.checkedout(),
        'overflow': pool.overflow(),
        'invalid': pool.invalid()
    }

