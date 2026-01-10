"""
API Documentation for URL Shortener Service
Provides comprehensive OpenAPI/Swagger documentation for all endpoints
"""

from flask_restx import Api, Resource, fields, Namespace
from flask import Blueprint
from marshmallow import Schema, fields as ma_fields, validate
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
import json

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Initialize Flask-RESTX API
api = Api(
    api_bp,
    version='1.0',
    title='URL Shortener API',
    description='A comprehensive URL shortening service with analytics, fraud detection, and user management',
    contact='support@urlshortener.com',
    contact_url='https://github.com/Guerlens50/url-shortener',
    license='MIT',
    license_url='https://opensource.org/licenses/MIT',
    doc='/docs/',
    prefix='/api/v1'
)

# Create namespaces for better organization
auth_ns = Namespace('auth', description='Authentication operations')
url_ns = Namespace('urls', description='URL shortening operations')
analytics_ns = Namespace('analytics', description='Analytics and statistics')
admin_ns = Namespace('admin', description='Administrative operations')

# Add namespaces to API
api.add_namespace(auth_ns)
api.add_namespace(url_ns)
api.add_namespace(analytics_ns)
api.add_namespace(admin_ns)

# =============================================================================
# Request/Response Models
# =============================================================================

# Authentication Models
signup_model = api.model('SignupRequest', {
    'username': fields.String(required=True, description='Unique username', example='john_doe'),
    'password': fields.String(required=True, description='User password (min 8 chars)', example='securepassword123')
})

login_model = api.model('LoginRequest', {
    'username': fields.String(required=True, description='Username', example='john_doe'),
    'password': fields.String(required=True, description='User password', example='securepassword123')
})

token_response_model = api.model('TokenResponse', {
    'access_token': fields.String(description='JWT access token (15 min expiry)', example='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...'),
    'refresh_token': fields.String(description='JWT refresh token (30 day expiry)', example='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...')
})

# URL Models
shorten_request_model = api.model('ShortenRequest', {
    'url': fields.String(required=True, description='Original URL to shorten', example='https://www.example.com/very/long/url'),
    'code': fields.String(required=False, description='Custom short code (optional)', example='mycode')
})

shorten_response_model = api.model('ShortenResponse', {
    'short_url': fields.String(description='Generated short URL', example='http://localhost:5000/abc12345')
})

url_stats_model = api.model('URLStats', {
    'original_url': fields.String(description='Original URL', example='https://www.example.com/very/long/url'),
    'clicks': fields.Integer(description='Total click count', example=42)
})

# Analytics Models
hourly_analytics_model = api.model('HourlyAnalytics', {
    'hour': fields.String(description='Hour timestamp', example='2024-01-15 14:00'),
    'clicks': fields.Integer(description='Clicks in this hour', example=5),
    'unique_visitors': fields.Integer(description='Unique visitors in this hour', example=3),
    'suspicious_clicks': fields.Integer(description='Suspicious clicks in this hour', example=1)
})

referrer_model = api.model('Referrer', {
    'referrer': fields.String(description='Referrer URL', example='https://google.com'),
    'clicks': fields.Integer(description='Clicks from this referrer', example=10)
})

analytics_response_model = api.model('AnalyticsResponse', {
    'hourly': fields.List(fields.Nested(hourly_analytics_model), description='Hourly analytics data'),
    'top_referrers': fields.List(fields.Nested(referrer_model), description='Top referrers')
})

trending_url_model = api.model('TrendingURL', {
    'url_id': fields.String(description='URL ID', example='uuid-123'),
    'trending_score': fields.Float(description='Trending score', example=15.5)
})

# Error Models
error_model = api.model('Error', {
    'error': fields.String(description='Error message', example='Invalid URL provided'),
    'code': fields.String(description='Error code', example='INVALID_URL')
})

validation_error_model = api.model('ValidationError', {
    'error': fields.String(description='Validation error message', example='Username is required'),
    'field': fields.String(description='Field that failed validation', example='username')
})

# Health Check Models
health_model = api.model('HealthCheck', {
    'status': fields.String(description='Service status', example='healthy'),
    'version': fields.String(description='API version', example='1.0.0'),
    'timestamp': fields.String(description='Current timestamp', example='2024-01-15T10:30:00Z'),
    'services': fields.Raw(description='Service dependencies status')
})

# =============================================================================
# API Documentation Decorators
# =============================================================================

def api_doc(endpoint_name, description, tags=None):
    """Decorator to add API documentation to endpoints"""
    def decorator(func):
        func.__api_doc__ = {
            'name': endpoint_name,
            'description': description,
            'tags': tags or []
        }
        return func
    return decorator

# =============================================================================
# OpenAPI Specification Generator
# =============================================================================

def create_openapi_spec():
    """Create OpenAPI specification for the API"""
    spec = APISpec(
        title="URL Shortener API",
        version="1.0.0",
        openapi_version="3.0.2",
        plugins=[FlaskPlugin(), MarshmallowPlugin()],
        info={
            "description": "A comprehensive URL shortening service with analytics, fraud detection, and user management",
            "contact": {
                "name": "API Support",
                "email": "support@urlshortener.com",
                "url": "https://github.com/Guerlens50/url-shortener"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        servers=[
            {
                "url": "http://localhost:5000",
                "description": "Development server"
            },
            {
                "url": "https://api.urlshortener.com",
                "description": "Production server"
            }
        ]
    )
    
    return spec

# =============================================================================
# API Documentation Routes
# =============================================================================

@api_bp.route('/openapi.json')
def openapi_spec():
    """Return OpenAPI specification as JSON"""
    spec = create_openapi_spec()
    return json.dumps(spec.to_dict(), indent=2)

@api_bp.route('/docs')
def api_docs():
    """Serve API documentation"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>URL Shortener API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui.css" />
        <style>
            html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
            *, *:before, *:after { box-sizing: inherit; }
            body { margin:0; background: #fafafa; }
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui-bundle.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui-standalone-preset.js"></script>
        <script>
            window.onload = function() {
                const ui = SwaggerUIBundle({
                    url: '/api/v1/openapi.json',
                    dom_id: '#swagger-ui',
                    deepLinking: true,
                    presets: [
                        SwaggerUIBundle.presets.apis,
                        SwaggerUIStandalonePreset
                    ],
                    plugins: [
                        SwaggerUIBundle.plugins.DownloadUrl
                    ],
                    layout: "StandaloneLayout"
                });
            };
        </script>
    </body>
    </html>
    '''

# =============================================================================
# Export API components for use in main app
# =============================================================================

def get_api_blueprint():
    """Get the API blueprint for registration in main app"""
    return api_bp

def get_api():
    """Get the Flask-RESTX API instance"""
    return api

def get_namespaces():
    """Get all API namespaces"""
    return {
        'auth': auth_ns,
        'urls': url_ns,
        'analytics': analytics_ns,
        'admin': admin_ns
    }
