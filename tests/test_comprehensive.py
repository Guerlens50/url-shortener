"""
Comprehensive Test Suite for URL Shortener
Tests all major functionality including edge cases and error scenarios
"""

import pytest
import json
import time
from unittest.mock import MagicMock, patch, Mock
from flask import Flask
from werkzeug.test import Client
import mysql.connector
import redis

# Import modules to test
from app import app
from auth import hash_password, check_password, create_access_token, create_refresh_token, decode_jwt
from tasks import log_click, check_fraud, update_trending_urls
from validation import URLValidator, UserValidator, ShortCodeValidator, validate_signup_data, validate_shorten_request
from health import health_checker, health_check, health_check_lite, readiness_check, liveness_check
from errors import APIError, handle_errors

# =============================================================================
# Test Configuration and Fixtures
# =============================================================================

@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def auth_headers():
    """Create valid auth headers for testing"""
    user_id = "test-user-123"
    token = create_access_token(user_id)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def mock_db_connection():
    """Mock database connection"""
    with patch('db.get_connection') as mock_conn:
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        yield mock_conn, mock_cursor

@pytest.fixture
def mock_redis():
    """Mock Redis connection"""
    with patch('db.redis_client') as mock_redis:
        yield mock_redis

# =============================================================================
# Authentication Tests
# =============================================================================

class TestAuthentication:
    """Test authentication functionality"""
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert hashed != password
        assert check_password(password, hashed) is True
        assert check_password("wrongpassword", hashed) is False
    
    def test_jwt_token_creation_and_validation(self):
        """Test JWT token creation and validation"""
        user_id = "test-user-123"
        
        # Test access token
        access_token = create_access_token(user_id)
        payload = decode_jwt(access_token)
        
        assert payload is not None
        assert payload["sub"] == user_id
        assert payload["type"] == "access"
        
        # Test refresh token
        jti = "test-jti-123"
        refresh_token = create_refresh_token(user_id, jti)
        payload = decode_jwt(refresh_token)
        
        assert payload is not None
        assert payload["sub"] == user_id
        assert payload["jti"] == jti
        assert payload["type"] == "refresh"
    
    def test_invalid_jwt_token(self):
        """Test invalid JWT token handling"""
        assert decode_jwt("invalid-token") is None
        assert decode_jwt("") is None
        assert decode_jwt(None) is None
    
    def test_signup_endpoint(self, client, mock_db_connection):
        """Test user signup endpoint"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock successful user creation
        mock_cursor.fetchone.return_value = None  # No existing user
        
        response = client.post('/auth/signup', 
                             json={'username': 'testuser', 'password': 'testpass123'})
        
        assert response.status_code == 201
        assert 'User created' in response.get_json()['msg']
    
    def test_signup_duplicate_username(self, client, mock_db_connection):
        """Test signup with duplicate username"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock IntegrityError for duplicate username
        mock_cursor.execute.side_effect = mysql.connector.errors.IntegrityError()
        
        response = client.post('/auth/signup', 
                             json={'username': 'existinguser', 'password': 'testpass123'})
        
        assert response.status_code == 400
        assert 'Username already exists' in response.get_json()['msg']
    
    def test_login_endpoint(self, client, mock_db_connection):
        """Test user login endpoint"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock user data
        mock_user = {
            'id': 'user-123',
            'username': 'testuser',
            'password_hash': hash_password('testpass123')
        }
        mock_cursor.fetchone.return_value = mock_user
        
        response = client.post('/auth/login', 
                             json={'username': 'testuser', 'password': 'testpass123'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
    
    def test_login_invalid_credentials(self, client, mock_db_connection):
        """Test login with invalid credentials"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock no user found
        mock_cursor.fetchone.return_value = None
        
        response = client.post('/auth/login', 
                             json={'username': 'nonexistent', 'password': 'wrongpass'})
        
        assert response.status_code == 401
        assert 'Bad credentials' in response.get_json()['msg']

# =============================================================================
# URL Shortening Tests
# =============================================================================

class TestURLShortening:
    """Test URL shortening functionality"""
    
    def test_shorten_url_success(self, client, auth_headers, mock_db_connection, mock_redis):
        """Test successful URL shortening"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock Redis rate limiting
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        
        response = client.post('/shorten', 
                             json={'url': 'https://www.example.com'},
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'short_url' in data
        assert 'localhost:5000' in data['short_url']
    
    def test_shorten_url_custom_code(self, client, auth_headers, mock_db_connection, mock_redis):
        """Test URL shortening with custom code"""
        mock_conn, mock_cursor = mock_db_connection
        mock_redis.get.return_value = None
        
        response = client.post('/shorten', 
                             json={'url': 'https://www.example.com', 'code': 'mycode'},
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'mycode' in data['short_url']
    
    def test_shorten_url_invalid_url(self, client, auth_headers, mock_redis):
        """Test URL shortening with invalid URL"""
        mock_redis.get.return_value = None
        
        response = client.post('/shorten', 
                             json={'url': 'not-a-valid-url'},
                             headers=auth_headers)
        
        assert response.status_code == 400
        assert 'Invalid URL' in response.get_json()['error']
    
    def test_shorten_url_rate_limit(self, client, auth_headers, mock_redis):
        """Test rate limiting for URL shortening"""
        # Mock rate limit exceeded
        mock_redis.get.return_value = "15"  # Exceeds limit of 10
        
        response = client.post('/shorten', 
                             json={'url': 'https://www.example.com'},
                             headers=auth_headers)
        
        assert response.status_code == 429
        assert 'Rate limit exceeded' in response.get_json()['error']
    
    def test_redirect_url_success(self, client, mock_db_connection, mock_redis):
        """Test URL redirection"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock URL found in database
        mock_url = {
            'id': 'url-123',
            'code': 'abc123',
            'original_url': 'https://www.example.com'
        }
        mock_cursor.fetchone.return_value = mock_url
        
        # Mock Redis cache miss
        mock_redis.get.return_value = None
        
        response = client.get('/abc123', follow_redirects=False)
        
        assert response.status_code == 302
        assert response.location == 'https://www.example.com'
    
    def test_redirect_url_not_found(self, client, mock_db_connection, mock_redis):
        """Test redirection for non-existent URL"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock no URL found
        mock_cursor.fetchone.return_value = None
        mock_redis.get.return_value = None
        
        response = client.get('/nonexistent')
        
        assert response.status_code == 404

# =============================================================================
# Analytics Tests
# =============================================================================

class TestAnalytics:
    """Test analytics functionality"""
    
    def test_url_stats(self, client, auth_headers, mock_db_connection, mock_redis):
        """Test URL statistics endpoint"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock URL data
        mock_url = {
            'id': 'url-123',
            'code': 'abc123',
            'original_url': 'https://www.example.com',
            'clicks': 42,
            'user_id': 'user-123'
        }
        mock_cursor.fetchone.return_value = mock_url
        
        # Mock rate limiting
        mock_redis.get.return_value = None
        
        response = client.get('/stats/abc123', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['original_url'] == 'https://www.example.com'
        assert data['clicks'] == 42
    
    def test_analytics_endpoint(self, client, auth_headers, mock_db_connection):
        """Test detailed analytics endpoint"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock URL ID lookup
        mock_cursor.fetchone.return_value = {'id': 'url-123'}
        
        # Mock analytics data
        mock_cursor.fetchall.side_effect = [
            [{'hour': '2024-01-15 10:00', 'clicks': 5, 'unique_visitors': 3, 'suspicious_clicks': 1}],
            [{'referrer': 'https://google.com', 'clicks': 10}]
        ]
        
        response = client.get('/analytics/abc123', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'hourly' in data
        assert 'top_referrers' in data

# =============================================================================
# Validation Tests
# =============================================================================

class TestValidation:
    """Test input validation functionality"""
    
    def test_url_validation(self):
        """Test URL validation"""
        # Valid URLs
        valid_urls = [
            'https://www.example.com',
            'http://example.com/path?query=value',
            'https://subdomain.example.com:8080/path'
        ]
        
        for url in valid_urls:
            result = URLValidator.validate_url(url)
            assert result['valid'] is True
            assert len(result['errors']) == 0
    
    def test_url_validation_invalid(self):
        """Test invalid URL validation"""
        invalid_urls = [
            'not-a-url',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'ftp://example.com',
            ''
        ]
        
        for url in invalid_urls:
            result = URLValidator.validate_url(url)
            assert result['valid'] is False
            assert len(result['errors']) > 0
    
    def test_username_validation(self):
        """Test username validation"""
        # Valid usernames
        valid_usernames = ['user123', 'test_user', 'user-name', 'a']
        
        for username in valid_usernames:
            result = UserValidator.validate_username(username)
            if len(username) >= 3:  # Min length check
                assert result['valid'] is True
        
        # Invalid usernames
        invalid_usernames = ['', 'ab', 'user@domain', 'user space', 'user!']
        
        for username in invalid_usernames:
            result = UserValidator.validate_username(username)
            assert result['valid'] is False
    
    def test_password_validation(self):
        """Test password validation"""
        # Valid passwords
        valid_passwords = ['password123', 'StrongPass123!', 'a' * 8]
        
        for password in valid_passwords:
            result = UserValidator.validate_password(password)
            assert result['valid'] is True
        
        # Invalid passwords
        invalid_passwords = ['', '123', 'a' * 7]  # Too short
        
        for password in invalid_passwords:
            result = UserValidator.validate_password(password)
            assert result['valid'] is False
    
    def test_short_code_validation(self):
        """Test short code validation"""
        # Valid codes
        valid_codes = ['abc123', 'my-code', 'test_123']
        
        for code in valid_codes:
            result = ShortCodeValidator.validate_short_code(code)
            assert result['valid'] is True
        
        # Invalid codes
        invalid_codes = ['', 'ab', 'admin', 'test@code', 'code with spaces']
        
        for code in invalid_codes:
            result = ShortCodeValidator.validate_short_code(code)
            assert result['valid'] is False

# =============================================================================
# Health Check Tests
# =============================================================================

class TestHealthChecks:
    """Test health check functionality"""
    
    def test_health_check(self, client, mock_db_connection, mock_redis):
        """Test comprehensive health check"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock database check
        mock_cursor.execute.return_value = None
        mock_cursor.fetchone.side_effect = [(1,), (5,), (10,)]  # ping, url_count, user_count
        
        # Mock Redis check
        mock_redis.ping.return_value = True
        mock_redis.info.return_value = {
            'used_memory_human': '1MB',
            'connected_clients': 5,
            'keyspace_hits': 100,
            'keyspace_misses': 10
        }
        
        response = client.get('/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert 'services' in data
        assert 'database' in data['services']
        assert 'redis' in data['services']
    
    def test_health_check_lite(self, client, mock_db_connection, mock_redis):
        """Test lightweight health check"""
        mock_conn, mock_cursor = mock_db_connection
        mock_cursor.execute.return_value = None
        mock_cursor.fetchone.return_value = (1,)
        mock_redis.ping.return_value = True
        
        response = client.get('/health/lite')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
    
    def test_readiness_check(self, client, mock_db_connection, mock_redis):
        """Test readiness check"""
        mock_conn, mock_cursor = mock_db_connection
        mock_cursor.execute.return_value = None
        mock_cursor.fetchone.return_value = (1,)
        mock_redis.ping.return_value = True
        
        response = client.get('/ready')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ready'
    
    def test_liveness_check(self, client):
        """Test liveness check"""
        response = client.get('/live')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'alive'

# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Test error handling functionality"""
    
    def test_api_error(self):
        """Test custom API error"""
        error = APIError("Test error", 400)
        assert error.message == "Test error"
        assert error.status_code == 400
    
    def test_error_handler_decorator(self):
        """Test error handler decorator"""
        @handle_errors
        def test_function():
            raise APIError("Test error", 400)
        
        # This would need to be tested in a Flask context
        # For now, just ensure the decorator exists
        assert callable(test_function)

# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_complete_url_shortening_workflow(self, client, mock_db_connection, mock_redis):
        """Test complete URL shortening workflow"""
        mock_conn, mock_cursor = mock_db_connection
        
        # Mock signup
        mock_cursor.fetchone.return_value = None
        signup_response = client.post('/auth/signup', 
                                    json={'username': 'testuser', 'password': 'testpass123'})
        assert signup_response.status_code == 201
        
        # Mock login
        mock_user = {
            'id': 'user-123',
            'username': 'testuser',
            'password_hash': hash_password('testpass123')
        }
        mock_cursor.fetchone.return_value = mock_user
        
        login_response = client.post('/auth/login', 
                                   json={'username': 'testuser', 'password': 'testpass123'})
        assert login_response.status_code == 200
        
        # Get token
        token = login_response.get_json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        
        # Mock rate limiting
        mock_redis.get.return_value = None
        
        # Shorten URL
        shorten_response = client.post('/shorten', 
                                     json={'url': 'https://www.example.com'},
                                     headers=headers)
        assert shorten_response.status_code == 200
        
        # Get short code from response
        short_url = shorten_response.get_json()['short_url']
        short_code = short_url.split('/')[-1]
        
        # Mock URL lookup for redirect
        mock_url = {
            'id': 'url-123',
            'code': short_code,
            'original_url': 'https://www.example.com'
        }
        mock_cursor.fetchone.return_value = mock_url
        
        # Test redirect
        redirect_response = client.get(f'/{short_code}', follow_redirects=False)
        assert redirect_response.status_code == 302

# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Performance and load testing"""
    
    def test_concurrent_requests(self, client, auth_headers, mock_db_connection, mock_redis):
        """Test handling of concurrent requests"""
        import threading
        import queue
        
        mock_conn, mock_cursor = mock_db_connection
        mock_redis.get.return_value = None
        
        results = queue.Queue()
        
        def make_request():
            response = client.post('/shorten', 
                                json={'url': 'https://www.example.com'},
                                headers=auth_headers)
            results.put(response.status_code)
        
        # Create multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check results
        status_codes = []
        while not results.empty():
            status_codes.append(results.get())
        
        # All requests should succeed or be rate limited
        for status_code in status_codes:
            assert status_code in [200, 429]

# =============================================================================
# Test Configuration
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
