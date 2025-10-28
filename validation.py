"""
Enhanced Input Validation Module
Provides comprehensive input validation for all API endpoints
"""

import re
import validators
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
from marshmallow import Schema, fields, validate, ValidationError
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom validation error with field-specific information"""
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)

# =============================================================================
# URL Validation
# =============================================================================

class URLValidator:
    """Enhanced URL validation with security checks"""
    
    # Dangerous URL patterns
    DANGEROUS_PATTERNS = [
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'file:',
        r'ftp:',
        r'tel:',
        r'mailto:',
    ]
    
    # Allowed protocols
    ALLOWED_PROTOCOLS = ['http', 'https']
    
    # Maximum URL length
    MAX_URL_LENGTH = 2048
    
    # Suspicious domains (can be expanded)
    SUSPICIOUS_DOMAINS = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1'
    ]
    
    @classmethod
    def validate_url(cls, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL validation
        Returns validation result with details
        """
        result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'sanitized_url': None
        }
        
        if not url:
            result['errors'].append('URL is required')
            return result
        
        # Check length
        if len(url) > cls.MAX_URL_LENGTH:
            result['errors'].append(f'URL too long (max {cls.MAX_URL_LENGTH} characters)')
            return result
        
        # Check for dangerous patterns
        url_lower = url.lower()
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern in url_lower:
                result['errors'].append(f'Dangerous URL pattern detected: {pattern}')
                return result
        
        # Basic URL validation
        if not validators.url(url):
            result['errors'].append('Invalid URL format')
            return result
        
        # Parse URL for additional checks
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if parsed.scheme not in cls.ALLOWED_PROTOCOLS:
                result['errors'].append(f'Protocol not allowed: {parsed.scheme}')
                return result
            
            # Check for suspicious domains
            if parsed.hostname in cls.SUSPICIOUS_DOMAINS:
                result['warnings'].append(f'Suspicious domain: {parsed.hostname}')
            
            # Check for IP addresses (might be suspicious)
            if cls._is_ip_address(parsed.hostname):
                result['warnings'].append('URL uses IP address instead of domain name')
            
            # Sanitize URL (remove fragments, normalize)
            sanitized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                sanitized += f"?{parsed.query}"
            result['sanitized_url'] = sanitized
            
            result['valid'] = True
            
        except Exception as e:
            result['errors'].append(f'URL parsing error: {str(e)}')
        
        return result
    
    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

# =============================================================================
# User Input Validation
# =============================================================================

class UserValidator:
    """User-related input validation"""
    
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 50
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    
    # Username allowed characters
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Password strength requirements
    PASSWORD_PATTERNS = {
        'lowercase': re.compile(r'[a-z]'),
        'uppercase': re.compile(r'[A-Z]'),
        'digit': re.compile(r'\d'),
        'special': re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    }
    
    @classmethod
    def validate_username(cls, username: str) -> Dict[str, Any]:
        """Validate username"""
        result = {'valid': False, 'errors': [], 'warnings': []}
        
        if not username:
            result['errors'].append('Username is required')
            return result
        
        if len(username) < cls.USERNAME_MIN_LENGTH:
            result['errors'].append(f'Username too short (min {cls.USERNAME_MIN_LENGTH} characters)')
        
        if len(username) > cls.USERNAME_MAX_LENGTH:
            result['errors'].append(f'Username too long (max {cls.USERNAME_MAX_LENGTH} characters)')
        
        if not cls.USERNAME_PATTERN.match(username):
            result['errors'].append('Username can only contain letters, numbers, underscores, and hyphens')
        
        if not result['errors']:
            result['valid'] = True
        
        return result
    
    @classmethod
    def validate_password(cls, password: str) -> Dict[str, Any]:
        """Validate password strength"""
        result = {'valid': False, 'errors': [], 'warnings': [], 'strength': 'weak'}
        
        if not password:
            result['errors'].append('Password is required')
            return result
        
        if len(password) < cls.PASSWORD_MIN_LENGTH:
            result['errors'].append(f'Password too short (min {cls.PASSWORD_MIN_LENGTH} characters)')
        
        if len(password) > cls.PASSWORD_MAX_LENGTH:
            result['errors'].append(f'Password too long (max {cls.PASSWORD_MAX_LENGTH} characters)')
        
        # Check password strength
        strength_score = 0
        for pattern_name, pattern in cls.PASSWORD_PATTERNS.items():
            if pattern.search(password):
                strength_score += 1
            else:
                result['warnings'].append(f'Password should contain {pattern_name} characters')
        
        # Determine strength
        if strength_score >= 4:
            result['strength'] = 'strong'
        elif strength_score >= 3:
            result['strength'] = 'medium'
        else:
            result['strength'] = 'weak'
            result['warnings'].append('Password is weak, consider using a stronger password')
        
        if not result['errors']:
            result['valid'] = True
        
        return result

# =============================================================================
# Short Code Validation
# =============================================================================

class ShortCodeValidator:
    """Short code validation"""
    
    MIN_LENGTH = 3
    MAX_LENGTH = 10
    ALLOWED_CHARACTERS = re.compile(r'^[a-zA-Z0-9_-]+$')
    RESERVED_CODES = [
        'admin', 'api', 'docs', 'health', 'metrics', 'login', 'logout',
        'signup', 'auth', 'static', 'assets', 'www', 'mail', 'ftp',
        'root', 'test', 'demo', 'example', 'help', 'support'
    ]
    
    @classmethod
    def validate_short_code(cls, code: str) -> Dict[str, Any]:
        """Validate custom short code"""
        result = {'valid': False, 'errors': [], 'warnings': []}
        
        if not code:
            result['errors'].append('Short code is required')
            return result
        
        if len(code) < cls.MIN_LENGTH:
            result['errors'].append(f'Short code too short (min {cls.MIN_LENGTH} characters)')
        
        if len(code) > cls.MAX_LENGTH:
            result['errors'].append(f'Short code too long (max {cls.MAX_LENGTH} characters)')
        
        if not cls.ALLOWED_CHARACTERS.match(code):
            result['errors'].append('Short code can only contain letters, numbers, underscores, and hyphens')
        
        if code.lower() in cls.RESERVED_CODES:
            result['errors'].append('Short code is reserved and cannot be used')
        
        if not result['errors']:
            result['valid'] = True
        
        return result

# =============================================================================
# Marshmallow Schemas
# =============================================================================

class SignupSchema(Schema):
    """Signup request validation schema"""
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=UserValidator.USERNAME_MIN_LENGTH, max=UserValidator.USERNAME_MAX_LENGTH),
            validate.Regexp(UserValidator.USERNAME_PATTERN, error='Invalid username format')
        ]
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=UserValidator.PASSWORD_MIN_LENGTH, max=UserValidator.PASSWORD_MAX_LENGTH)
    )

class LoginSchema(Schema):
    """Login request validation schema"""
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class ShortenURLSchema(Schema):
    """URL shortening request validation schema"""
    url = fields.Str(required=True)
    code = fields.Str(
        required=False,
        allow_none=True,
        validate=[
            validate.Length(min=ShortCodeValidator.MIN_LENGTH, max=ShortCodeValidator.MAX_LENGTH),
            validate.Regexp(ShortCodeValidator.ALLOWED_CHARACTERS, error='Invalid short code format')
        ]
    )

# =============================================================================
# Validation Decorators
# =============================================================================

def validate_input(schema_class):
    """Decorator to validate input using Marshmallow schemas"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                schema = schema_class()
                data = schema.load(request.get_json() or {})
                request.validated_data = data
                return func(*args, **kwargs)
            except ValidationError as e:
                return jsonify({
                    'error': 'Validation failed',
                    'details': e.messages
                }), 400
        return wrapper
    return decorator

# =============================================================================
# Comprehensive Validation Functions
# =============================================================================

def validate_signup_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive signup data validation"""
    result = {'valid': False, 'errors': [], 'warnings': []}
    
    # Validate username
    username_result = UserValidator.validate_username(data.get('username', ''))
    if not username_result['valid']:
        result['errors'].extend(username_result['errors'])
    result['warnings'].extend(username_result['warnings'])
    
    # Validate password
    password_result = UserValidator.validate_password(data.get('password', ''))
    if not password_result['valid']:
        result['errors'].extend(password_result['errors'])
    result['warnings'].extend(password_result['warnings'])
    
    if not result['errors']:
        result['valid'] = True
    
    return result

def validate_shorten_request(data: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive URL shortening request validation"""
    result = {'valid': False, 'errors': [], 'warnings': [], 'sanitized_data': {}}
    
    # Validate URL
    url_result = URLValidator.validate_url(data.get('url', ''))
    if not url_result['valid']:
        result['errors'].extend(url_result['errors'])
    else:
        result['sanitized_data']['url'] = url_result['sanitized_url']
    result['warnings'].extend(url_result['warnings'])
    
    # Validate custom code if provided
    if data.get('code'):
        code_result = ShortCodeValidator.validate_short_code(data['code'])
        if not code_result['valid']:
            result['errors'].extend(code_result['errors'])
        else:
            result['sanitized_data']['code'] = data['code']
        result['warnings'].extend(code_result['warnings'])
    
    if not result['errors']:
        result['valid'] = True
    
    return result

# =============================================================================
# Rate Limiting Validation
# =============================================================================

def validate_rate_limit_headers(request) -> Dict[str, Any]:
    """Validate rate limiting headers and client information"""
    result = {'valid': True, 'warnings': []}
    
    # Check for suspicious headers
    suspicious_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP'
    ]
    
    for header in suspicious_headers:
        if header in request.headers:
            value = request.headers[header]
            if ',' in value:  # Multiple IPs in forwarded header
                result['warnings'].append(f'Multiple IPs in {header}: {value}')
    
    # Check User-Agent
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent:
        result['warnings'].append('Missing User-Agent header')
    elif len(user_agent) > 500:
        result['warnings'].append('Suspiciously long User-Agent')
    
    return result
