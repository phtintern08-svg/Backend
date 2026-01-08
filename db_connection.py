"""
Database Connection Management
Provides connection retry logic and health monitoring

⚠️ CRITICAL: DO NOT IMPORT THIS MODULE IN FLASK APP
This module contains raw SQLAlchemy engine management that conflicts with Flask-SQLAlchemy.

Flask-SQLAlchemy automatically manages engines and connections.
Mixing both causes "connection is closed" errors in Passenger workers.

✅ CORRECT: Use only Flask-SQLAlchemy
❌ WRONG: Import create_engine_with_retry or use manual engines

This file is kept for reference only - not used in the Flask application.
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


# REMOVED: Global event listeners - these interfere with Flask-SQLAlchemy's engine management
# Flask-SQLAlchemy manages engines and connections automatically
# Adding global listeners causes conflicts in Passenger workers with multiple engines
#
# If you need connection-level settings, configure them via SQLALCHEMY_ENGINE_OPTIONS
# in config.py using connect_args or pool_pre_ping
#
# @event.listens_for(Engine, "connect")  # ❌ REMOVED - conflicts with Flask-SQLAlchemy
# @event.listens_for(Pool, "connect")    # ❌ REMOVED - conflicts with Flask-SQLAlchemy


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

