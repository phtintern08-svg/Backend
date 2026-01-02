"""
Secure File Upload Utility
Provides secure file validation, storage, and management
"""
import os
import uuid
import logging
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import current_app
from config import Config
from logger_config import log_error_with_context, log_warning, log_info
from typing import Tuple, Optional, Dict, List

# Try to import python-magic (optional, falls back to magic bytes if not available)
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# File type definitions with MIME types and magic bytes
ALLOWED_MIME_TYPES = {
    'image': {
        'mimes': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
        'magic_bytes': {
            b'\xff\xd8\xff': 'image/jpeg',
            b'\x89PNG\r\n\x1a\n': 'image/png',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'RIFF': 'image/webp',  # WebP starts with RIFF
        },
        'max_size': 5 * 1024 * 1024,  # 5MB
    },
    'document': {
        'mimes': ['application/pdf', 'application/msword', 
                  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        'extensions': ['.pdf', '.doc', '.docx'],
        'magic_bytes': {
            b'%PDF': 'application/pdf',
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/msword',  # DOC
            b'PK\x03\x04': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # DOCX
        },
        'max_size': 10 * 1024 * 1024,  # 10MB
    },
    'quotation': {
        'mimes': ['application/pdf', 'application/vnd.ms-excel',
                  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        'extensions': ['.pdf', '.xls', '.xlsx'],
        'magic_bytes': {
            b'%PDF': 'application/pdf',
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/vnd.ms-excel',  # XLS
            b'PK\x03\x04': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # XLSX
        },
        'max_size': 10 * 1024 * 1024,  # 10MB
    }
}

# Endpoint-specific file type and size limits
ENDPOINT_LIMITS = {
    '/vendor/verification/upload': {
        'allowed_types': ['image', 'document'],
        'max_size': 10 * 1024 * 1024,  # 10MB
    },
    '/rider/verification/upload': {
        'allowed_types': ['image', 'document'],
        'max_size': 10 * 1024 * 1024,  # 10MB
    },
    '/rider/upload-documents': {
        'allowed_types': ['image', 'document'],
        'max_size': 10 * 1024 * 1024,  # 10MB
    },
    '/vendor/submit-quotation': {
        'allowed_types': ['quotation'],
        'max_size': 10 * 1024 * 1024,  # 10MB
    },
    '/rider/delivery': {
        'allowed_types': ['image'],
        'max_size': 5 * 1024 * 1024,  # 5MB for proof images
    },
}


def get_file_mime_type(file_data: bytes, filename: str) -> Optional[str]:
    """
    Detect MIME type from file content (magic bytes) and filename
    
    Args:
        file_data: File content as bytes
        filename: Original filename
        
    Returns:
        Detected MIME type or None
    """
    # Try python-magic first (more accurate)
    if MAGIC_AVAILABLE:
        try:
            mime = magic.Magic(mime=True)
            detected = mime.from_buffer(file_data[:1024])  # Check first 1KB
            if detected:
                return detected
        except (AttributeError, Exception):
            # python-magic not working, fall back to magic bytes
            pass
    
    # Check magic bytes
    for file_type, config in ALLOWED_MIME_TYPES.items():
        for magic_bytes, mime_type in config['magic_bytes'].items():
            if file_data.startswith(magic_bytes):
                return mime_type
    
    # Fall back to extension-based detection
    ext = os.path.splitext(filename.lower())[1]
    for file_type, config in ALLOWED_MIME_TYPES.items():
        if ext in config['extensions']:
            return config['mimes'][0]  # Return first MIME type for this extension
    
    return None


def validate_file_content(file_data: bytes, filename: str, allowed_types: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate file content matches declared type
    
    Args:
        file_data: File content as bytes
        filename: Original filename
        allowed_types: List of allowed file type categories
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file_data:
        return False, "File is empty"
    
    # Detect actual MIME type from content
    detected_mime = get_file_mime_type(file_data, filename)
    
    if not detected_mime:
        return False, "File type could not be determined from content"
    
    # Check if detected MIME type is in allowed types
    for file_type in allowed_types:
        if file_type in ALLOWED_MIME_TYPES:
            if detected_mime in ALLOWED_MIME_TYPES[file_type]['mimes']:
                return True, None
    
    return False, f"File type {detected_mime} is not allowed. Allowed types: {', '.join(allowed_types)}"


def scan_file_for_viruses(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Scan file for viruses using ClamAV (if available)
    
    Args:
        file_path: Path to file to scan
        
    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        import pyclamd
        
        # Try to connect to ClamAV daemon
        try:
            cd = pyclamd.ClamdUnixSocket()
        except:
            try:
                cd = pyclamd.ClamdNetworkSocket()
            except:
                # ClamAV not available, skip scanning
                log_warning("ClamAV not available, skipping virus scan")
                return True, None
        
        # Scan the file
        result = cd.scan_file(file_path)
        if result:
            # Virus detected
            virus_name = result.get(file_path, {}).get('virus', 'Unknown')
            return False, f"Virus detected: {virus_name}"
        
        return True, None
        
    except ImportError:
        # pyclamd not installed, skip scanning
        log_warning("pyclamd not installed, skipping virus scan")
        return True, None
    except Exception as e:
        log_error_with_context(e, {"file_path": file_path}, level=logging.WARNING)
        # On error, allow file but log warning
        return True, None


def save_file_to_disk(file: FileStorage, subfolder: str, user_id: int, doc_type: str = '') -> Tuple[Optional[str], Optional[str]]:
    """
    Save file to filesystem with secure naming
    
    Args:
        file: Flask FileStorage object
        subfolder: Subfolder within uploads directory (e.g., 'vendor', 'rider')
        user_id: User ID for organizing files
        doc_type: Document type (optional, for additional organization)
        
    Returns:
        Tuple of (file_path, error_message)
    """
    try:
        # Get upload folder
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            return None, "Upload folder not configured"
        
        # Create subfolder structure: uploads/{subfolder}/{user_id}/
        user_folder = os.path.join(upload_folder, subfolder, str(user_id))
        os.makedirs(user_folder, exist_ok=True)
        
        # Generate secure filename
        original_filename = secure_filename(file.filename)
        name, ext = os.path.splitext(original_filename)
        
        # Generate unique filename to prevent collisions
        unique_id = str(uuid.uuid4())[:8]
        if doc_type:
            safe_filename = f"{doc_type}_{unique_id}{ext}"
        else:
            safe_filename = f"{name}_{unique_id}{ext}"
        
        file_path = os.path.join(user_folder, safe_filename)
        
        # Save file
        file.save(file_path)
        
        # Return relative path from uploads folder
        relative_path = os.path.join(subfolder, str(user_id), safe_filename)
        
        log_info(f"File saved: {relative_path}", {"user_id": user_id, "doc_type": doc_type})
        
        return relative_path, None
        
    except Exception as e:
        log_error_with_context(e, {"user_id": user_id, "doc_type": doc_type})
        return None, f"Failed to save file: {str(e)}"


def validate_and_save_file(
    file: FileStorage,
    endpoint: str,
    subfolder: str,
    user_id: int,
    doc_type: str = '',
    scan_virus: bool = False
) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Validate and save uploaded file
    
    Args:
        file: Flask FileStorage object
        endpoint: API endpoint path (for limit lookup)
        subfolder: Subfolder within uploads directory
        user_id: User ID
        doc_type: Document type
        scan_virus: Whether to scan for viruses (requires ClamAV)
        
    Returns:
        Tuple of (file_info_dict, error_message)
    """
    # Check if file is provided
    if not file or not file.filename:
        return None, "No file provided"
    
    # Get endpoint-specific limits
    limits = ENDPOINT_LIMITS.get(endpoint, {
        'allowed_types': ['image', 'document'],
        'max_size': 10 * 1024 * 1024,
    })
    
    allowed_types = limits['allowed_types']
    max_size = limits.get('max_size', 10 * 1024 * 1024)
    
    # Read file data
    file.seek(0)
    file_data = file.read()
    file.seek(0)  # Reset for saving
    
    file_size = len(file_data)
    
    # Check file size
    if file_size > max_size:
        return None, f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds maximum allowed size ({max_size / 1024 / 1024:.2f}MB)"
    
    if file_size == 0:
        return None, "File is empty"
    
    # Validate file content
    is_valid, error_msg = validate_file_content(file_data, file.filename, allowed_types)
    if not is_valid:
        return None, error_msg or "File validation failed"
    
    # Get detected MIME type
    detected_mime = get_file_mime_type(file_data, file.filename)
    
    # Save file to disk
    file_path, save_error = save_file_to_disk(file, subfolder, user_id, doc_type)
    if save_error:
        return None, save_error
    
    # Virus scanning (optional)
    if scan_virus:
        # Get absolute path for scanning
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        absolute_path = os.path.join(upload_folder, file_path)
        is_safe, virus_error = scan_file_for_viruses(absolute_path)
        if not is_safe:
            # Delete file if virus detected
            try:
                os.remove(absolute_path)
            except:
                pass
            return None, virus_error or "Virus detected in file"
    
    # Return file information
    file_info = {
        'path': file_path,
        'filename': secure_filename(file.filename),
        'original_filename': file.filename,
        'mimetype': detected_mime or file.content_type,
        'size': file_size,
        'secure_filename': os.path.basename(file_path),
    }
    
    return file_info, None


def get_file_path_from_db(relative_path: str) -> Optional[str]:
    """
    Get absolute file path from relative path stored in database
    
    Args:
        relative_path: Relative path stored in database
        
    Returns:
        Absolute file path or None
    """
    try:
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            return None
        
        return os.path.join(upload_folder, relative_path)
    except Exception:
        return None


def delete_file(relative_path: str) -> bool:
    """
    Delete file from filesystem
    
    Args:
        relative_path: Relative path to file
        
    Returns:
        True if deleted, False otherwise
    """
    try:
        file_path = get_file_path_from_db(relative_path)
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            log_info(f"File deleted: {relative_path}")
            return True
        return False
    except Exception as e:
        log_error_with_context(e, {"relative_path": relative_path})
        return False

