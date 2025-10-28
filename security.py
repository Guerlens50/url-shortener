"""
Security Enhancements Module
Provides comprehensive security features including CORS, security headers, and input sanitization
"""

import os
import re
from flask import Flask, request, jsonify, make_response
from functools import wraps
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# Security Headers
# =============================================================================

class SecurityHeaders:
    """Manages security headers for HTTP responses"""
    
    @staticmethod
    def add_security_headers(response):
        """Add comprehensive security headers to response"""
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' https://unpkg.com; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        
        # HTTP Strict Transport Security
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )
        
        # X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options
        response.headers['X-Frame-Options'] = 'DENY'
        
        # X-XSS-Protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=(), '
            'gyroscope=(), '
            'speaker=()'
        )
        
        return response

# =============================================================================
# Input Sanitization
# =============================================================================

class InputSanitizer:
    """Sanitizes user input to prevent XSS and injection attacks"""
    
    # Dangerous patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
        r'<style[^>]*>',
    ]
    
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
        r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
        r'(\b(OR|AND)\s+\'[^\']*\'\s*=\s*\'[^\']*\')',
        r'(\b(OR|AND)\s+\"[^\"]*\"\s*=\s*\"[^\"]*\")',
        r'(\b(OR|AND)\s+\w+\s*=\s*\w+)',
        r'(\b(OR|AND)\s+\w+\s*LIKE\s*[\'\"])',
        r'(\b(OR|AND)\s+\w+\s*IN\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*BETWEEN\s+\w+\s+AND\s+\w+)',
        r'(\b(OR|AND)\s+\w+\s*IS\s+NULL)',
        r'(\b(OR|AND)\s+\w+\s*IS\s+NOT\s+NULL)',
        r'(\b(OR|AND)\s+\w+\s*EXISTS\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+EXISTS\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*IN\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+IN\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*ANY\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*ALL\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*SOME\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+ANY\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+ALL\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+SOME\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*EXISTS\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+EXISTS\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*IN\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+IN\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*ANY\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*ALL\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*SOME\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+ANY\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+ALL\s*\([^)]*\))',
        r'(\b(OR|AND)\s+\w+\s*NOT\s+SOME\s*\([^)]*\))',
    ]
    
    @classmethod
    def sanitize_string(cls, input_string: str, max_length: int = 1000) -> str:
        """Sanitize a string input"""
        if not isinstance(input_string, str):
            return str(input_string)
        
        # Limit length
        if len(input_string) > max_length:
            input_string = input_string[:max_length]
        
        # Remove null bytes
        input_string = input_string.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        input_string = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_string)
        
        return input_string.strip()
    
    @classmethod
    def detect_xss(cls, input_string: str) -> bool:
        """Detect potential XSS attacks"""
        if not isinstance(input_string, str):
            return False
        
        input_lower = input_string.lower()
        
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        
        return False
    
    @classmethod
    def detect_sql_injection(cls, input_string: str) -> bool:
        """Detect potential SQL injection attacks"""
        if not isinstance(input_string, str):
            return False
        
        input_upper = input_string.upper()
        
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return True
        
        return False
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a dictionary of data"""
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            sanitized_key = cls.sanitize_string(str(key), 100)
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized_value = cls.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized_value = cls.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized_value = [cls.sanitize_string(str(item)) if isinstance(item, str) else item for item in value]
            else:
                sanitized_value = value
            
            sanitized[sanitized_key] = sanitized_value
        
        return sanitized

# =============================================================================
# Rate Limiting Enhancements
# =============================================================================

class EnhancedRateLimiter:
    """Enhanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.suspicious_ips = set()
        self.blocked_ips = set()
    
    def is_ip_suspicious(self, ip: str) -> bool:
        """Check if IP is marked as suspicious"""
        return ip in self.suspicious_ips
    
    def mark_ip_suspicious(self, ip: str):
        """Mark IP as suspicious"""
        self.suspicious_ips.add(ip)
        logger.warning(f"IP {ip} marked as suspicious")
    
    def block_ip(self, ip: str):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        logger.warning(f"IP {ip} blocked")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def get_rate_limit_key(self, identifier: str, endpoint: str) -> str:
        """Generate rate limit key"""
        return f"rate_limit:{identifier}:{endpoint}"

# =============================================================================
# Security Decorators
# =============================================================================

def require_https(f):
    """Decorator to require HTTPS"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure and not request.headers.get('X-Forwarded-Proto') == 'https':
            return jsonify({'error': 'HTTPS required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def validate_content_type(expected_types: list):
    """Decorator to validate content type"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_type = request.content_type
            if content_type not in expected_types:
                return jsonify({'error': f'Content-Type must be one of: {", ".join(expected_types)}'}), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_input(f):
    """Decorator to sanitize input data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            sanitized_data = InputSanitizer.sanitize_dict(request.get_json())
            request.sanitized_json = sanitized_data
        
        return f(*args, **kwargs)
    return decorated_function

def detect_attacks(f):
    """Decorator to detect potential attacks"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for XSS in request data
        if request.is_json:
            data = request.get_json()
            for key, value in data.items():
                if isinstance(value, str):
                    if InputSanitizer.detect_xss(value):
                        logger.warning(f"Potential XSS attack detected in {key}: {value}")
                        return jsonify({'error': 'Invalid input detected'}), 400
                    
                    if InputSanitizer.detect_sql_injection(value):
                        logger.warning(f"Potential SQL injection detected in {key}: {value}")
                        return jsonify({'error': 'Invalid input detected'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# Security Middleware
# =============================================================================

def setup_security_middleware(app: Flask):
    """Setup security middleware for Flask app"""
    
    @app.before_request
    def security_before_request():
        """Security checks before each request"""
        # Check for blocked IPs
        client_ip = request.remote_addr
        if hasattr(app, 'enhanced_rate_limiter'):
            if app.enhanced_rate_limiter.is_ip_blocked(client_ip):
                return jsonify({'error': 'Access denied'}), 403
        
        # Log suspicious requests
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) > 500:
            logger.warning(f"Suspicious request from {client_ip}: missing or long User-Agent")
    
    @app.after_request
    def security_after_request(response):
        """Add security headers after each request"""
        return SecurityHeaders.add_security_headers(response)

# =============================================================================
# Security Configuration
# =============================================================================

class SecurityConfig:
    """Security configuration management"""
    
    # Security settings
    ENABLE_HTTPS_REDIRECT = os.environ.get('ENABLE_HTTPS_REDIRECT', 'false').lower() == 'true'
    MAX_REQUEST_SIZE = int(os.environ.get('MAX_REQUEST_SIZE', '16777216'))  # 16MB
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8080').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_HEADERS = ['Content-Type', 'Authorization', 'X-Requested-With']
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'"
    }

# =============================================================================
# Export security components
# =============================================================================

security_headers = SecurityHeaders()
input_sanitizer = InputSanitizer()
enhanced_rate_limiter = EnhancedRateLimiter()
security_config = SecurityConfig()
