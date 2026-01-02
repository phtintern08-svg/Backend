"""
Input Validation and Sanitization Utilities
Provides centralized input validation and HTML sanitization
"""
import re
from marshmallow import Schema, fields, validate, ValidationError, pre_load
from marshmallow.validate import Length, Email, Regexp
import bleach
from config import Config


# HTML Sanitization Configuration
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'p': ['class'],
    'li': ['class']
}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def sanitize_html(html_content):
    """
    Sanitize HTML content to prevent XSS attacks
    
    Args:
        html_content: HTML string to sanitize
    
    Returns:
        str: Sanitized HTML
    """
    if not html_content:
        return ""
    
    # Clean HTML
    cleaned = bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )
    
    return cleaned


def sanitize_text(text):
    """
    Sanitize plain text by removing HTML tags
    
    Args:
        text: Text string to sanitize
    
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    return bleach.clean(text, tags=[], strip=True)


def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def validate_phone(phone):
    """Validate phone number format (Indian format)"""
    if not phone:
        return False
    # Indian phone: 10 digits, optionally with +91 prefix
    phone_pattern = r'^(\+91)?[6-9]\d{9}$'
    return bool(re.match(phone_pattern, phone.replace(' ', '').replace('-', '')))


def validate_pincode(pincode):
    """Validate Indian pincode (6 digits)"""
    if not pincode:
        return False
    pincode_pattern = r'^\d{6}$'
    return bool(re.match(pincode_pattern, str(pincode)))


# Validation Schemas using Marshmallow

class LoginSchema(Schema):
    """Schema for login validation"""
    identifier = fields.Str(required=True, validate=Length(min=1, max=255))
    password = fields.Str(required=True, validate=Length(min=1, max=255))


class RegisterSchema(Schema):
    """Schema for registration validation"""
    username = fields.Str(required=True, validate=Length(min=3, max=50))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=Length(min=8, max=128))
    phone = fields.Str(required=True, validate=Regexp(r'^(\+91)?[6-9]\d{9}$', error='Invalid phone number'))
    role = fields.Str(validate=validate.OneOf(['customer', 'vendor']), load_default='customer')
    business_name = fields.Str(validate=Length(max=255), allow_none=True)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Sanitize string inputs"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and key != 'password':  # Don't sanitize passwords
                    data[key] = sanitize_text(value)
        return data


class AddressSchema(Schema):
    """Schema for address validation"""
    address_line1 = fields.Str(required=True, validate=Length(min=1, max=255))
    address_line2 = fields.Str(validate=Length(max=255), allow_none=True)
    city = fields.Str(required=True, validate=Length(min=1, max=100))
    state = fields.Str(required=True, validate=Length(min=1, max=100))
    pincode = fields.Str(required=True, validate=Regexp(r'^\d{6}$', error='Invalid pincode'))
    country = fields.Str(validate=Length(max=100), load_default='India')
    address_type = fields.Str(validate=validate.OneOf(['home', 'work', 'other']), load_default='home')
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Sanitize string inputs"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    data[key] = sanitize_text(value)
        return data


class OrderSchema(Schema):
    """Schema for order creation validation"""
    customer_id = fields.Int(required=True)
    product_type = fields.Str(required=True, validate=Length(min=1, max=100))
    category = fields.Str(required=True, validate=Length(min=1, max=100))
    neck_type = fields.Str(validate=Length(max=50), allow_none=True)
    color = fields.Str(validate=Length(max=50), allow_none=True)
    fabric = fields.Str(validate=Length(max=100), allow_none=True)
    print_type = fields.Str(validate=Length(max=100), allow_none=True)
    quantity = fields.Int(required=True, validate=validate.Range(min=1, max=10000))
    delivery_date = fields.DateTime(allow_none=True)
    price_per_piece = fields.Decimal(required=True, validate=validate.Range(min=0))
    address_line1 = fields.Str(required=True, validate=Length(min=1, max=255))
    address_line2 = fields.Str(validate=Length(max=255), allow_none=True)
    city = fields.Str(required=True, validate=Length(min=1, max=100))
    state = fields.Str(required=True, validate=Length(min=1, max=100))
    pincode = fields.Str(required=True, validate=Regexp(r'^\d{6}$', error='Invalid pincode'))
    country = fields.Str(validate=Length(max=100), load_default='India')
    transaction_id = fields.Str(validate=Length(max=255), allow_none=True)
    sample_cost = fields.Decimal(validate=validate.Range(min=0), load_default=0.0)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Sanitize string inputs"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and key not in ['transaction_id']:  # Don't sanitize transaction IDs
                    data[key] = sanitize_text(value)
        return data


class ProfileUpdateSchema(Schema):
    """Schema for profile update validation"""
    username = fields.Str(validate=Length(min=3, max=50), allow_none=True)
    email = fields.Email(allow_none=True)
    phone = fields.Str(validate=Regexp(r'^(\+91)?[6-9]\d{9}$', error='Invalid phone number'), allow_none=True)
    business_name = fields.Str(validate=Length(max=255), allow_none=True)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Sanitize string inputs"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    data[key] = sanitize_text(value)
        return data


class CommentSchema(Schema):
    """Schema for comment/thread validation"""
    content = fields.Str(required=True, validate=Length(min=1, max=5000))
    thread_id = fields.Int(required=True)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Sanitize HTML content"""
        if isinstance(data, dict) and 'content' in data:
            data['content'] = sanitize_html(data['content'])
        return data


def validate_request_data(schema_class, data):
    """
    Validate request data against a schema
    
    Args:
        schema_class: Marshmallow Schema class
        data: Data dictionary to validate
    
    Returns:
        tuple: (validated_data, errors)
        - validated_data: Cleaned and validated data
        - errors: Dictionary of validation errors (empty if valid)
    """
    try:
        schema = schema_class()
        validated_data = schema.load(data)
        return validated_data, {}
    except ValidationError as err:
        return None, err.messages

