"""
URL Management Features
Provides URL expiration, custom domains, and bulk operations
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from flask import request, jsonify
from db import get_connection, safe_close
import mysql.connector
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# URL Expiration Management
# =============================================================================

class URLExpirationManager:
    """Manages URL expiration functionality"""
    
    @staticmethod
    def add_expiration_to_url(url_id: str, expires_at: datetime) -> bool:
        """Add expiration date to a URL"""
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE urls SET expires_at = %s WHERE id = %s",
                (expires_at, url_id)
            )
            conn.commit()
            
            cursor.close()
            safe_close(conn)
            return True
        except Exception as e:
            logger.error(f"Error adding expiration to URL {url_id}: {e}")
            return False
    
    @staticmethod
    def is_url_expired(url_id: str) -> bool:
        """Check if a URL has expired"""
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT expires_at FROM urls WHERE id = %s",
                (url_id,)
            )
            result = cursor.fetchone()
            
            cursor.close()
            safe_close(conn)
            
            if not result or not result['expires_at']:
                return False  # No expiration set
            
            return datetime.utcnow() > result['expires_at']
        except Exception as e:
            logger.error(f"Error checking URL expiration {url_id}: {e}")
            return False
    
    @staticmethod
    def get_expiring_urls(hours_ahead: int = 24) -> List[Dict[str, Any]]:
        """Get URLs that will expire within the specified hours"""
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                """
                SELECT id, code, original_url, expires_at, user_id
                FROM urls 
                WHERE expires_at IS NOT NULL 
                AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL %s HOUR)
                ORDER BY expires_at ASC
                """,
                (hours_ahead,)
            )
            
            results = cursor.fetchall()
            
            cursor.close()
            safe_close(conn)
            
            return results
        except Exception as e:
            logger.error(f"Error getting expiring URLs: {e}")
            return []

# =============================================================================
# Custom Domain Management
# =============================================================================

class CustomDomainManager:
    """Manages custom domain functionality"""
    
    ALLOWED_DOMAINS = os.environ.get('ALLOWED_DOMAINS', '').split(',')
    
    @classmethod
    def is_domain_allowed(cls, domain: str) -> bool:
        """Check if a domain is allowed for custom URLs"""
        if not cls.ALLOWED_DOMAINS or cls.ALLOWED_DOMAINS == ['']:
            return True  # No restrictions if not configured
        
        return domain.lower() in [d.lower().strip() for d in cls.ALLOWED_DOMAINS]
    
    @classmethod
    def validate_custom_domain(cls, domain: str) -> Dict[str, Any]:
        """Validate custom domain"""
        result = {'valid': False, 'errors': [], 'warnings': []}
        
        if not domain:
            result['errors'].append('Domain is required')
            return result
        
        # Basic domain validation
        if not domain.replace('.', '').replace('-', '').isalnum():
            result['errors'].append('Invalid domain format')
            return result
        
        # Check if domain is allowed
        if not cls.is_domain_allowed(domain):
            result['errors'].append(f'Domain {domain} is not allowed')
            return result
        
        result['valid'] = True
        return result

# =============================================================================
# Bulk Operations
# =============================================================================

class BulkURLManager:
    """Manages bulk URL operations"""
    
    MAX_BULK_URLS = 100
    
    @staticmethod
    def bulk_shorten_urls(urls: List[Dict[str, Any]], user_id: str) -> Dict[str, Any]:
        """Shorten multiple URLs in a single operation"""
        if len(urls) > BulkURLManager.MAX_BULK_URLS:
            return {
                'success': False,
                'error': f'Too many URLs. Maximum {BulkURLManager.MAX_BULK_URLS} allowed',
                'processed': 0,
                'results': []
            }
        
        results = []
        processed = 0
        
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            for url_data in urls:
                try:
                    original_url = url_data.get('url', '')
                    custom_code = url_data.get('code')
                    
                    # Generate code if not provided
                    if not custom_code:
                        import nanoid
                        custom_code = nanoid.generate(size=8)
                    
                    # Insert URL
                    cursor.execute(
                        "INSERT INTO urls (id, code, original_url, user_id) VALUES (%s, %s, %s, %s)",
                        (str(uuid4()), custom_code, original_url, user_id)
                    )
                    
                    results.append({
                        'original_url': original_url,
                        'short_code': custom_code,
                        'short_url': f"http://localhost:5000/{custom_code}",
                        'success': True
                    })
                    processed += 1
                    
                except mysql.connector.errors.IntegrityError:
                    results.append({
                        'original_url': url_data.get('url', ''),
                        'error': 'Short code already exists',
                        'success': False
                    })
                except Exception as e:
                    results.append({
                        'original_url': url_data.get('url', ''),
                        'error': str(e),
                        'success': False
                    })
            
            conn.commit()
            cursor.close()
            safe_close(conn)
            
            return {
                'success': True,
                'processed': processed,
                'total': len(urls),
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Bulk URL shortening error: {e}")
            return {
                'success': False,
                'error': str(e),
                'processed': processed,
                'results': results
            }

# =============================================================================
# URL Analytics Enhancement
# =============================================================================

class URLAnalyticsManager:
    """Enhanced URL analytics management"""
    
    @staticmethod
    def get_url_performance_metrics(url_id: str, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive performance metrics for a URL"""
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Get basic URL info
            cursor.execute(
                "SELECT code, original_url, clicks, created_at FROM urls WHERE id = %s",
                (url_id,)
            )
            url_info = cursor.fetchone()
            
            if not url_info:
                return {'error': 'URL not found'}
            
            # Get daily click counts
            cursor.execute(
                """
                SELECT DATE(clicked_at) as date, COUNT(*) as clicks
                FROM url_clicks 
                WHERE url_id = %s 
                AND clicked_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(clicked_at)
                ORDER BY date DESC
                """,
                (url_id, days)
            )
            daily_clicks = cursor.fetchall()
            
            # Get top countries
            cursor.execute(
                """
                SELECT 
                    CASE 
                        WHEN ip LIKE '192.168.%' OR ip LIKE '10.%' OR ip LIKE '172.%' THEN 'local'
                        ELSE 'external'
                    END as location_type,
                    COUNT(*) as clicks
                FROM url_clicks 
                WHERE url_id = %s
                GROUP BY location_type
                """,
                (url_id,)
            )
            location_stats = cursor.fetchall()
            
            # Get device breakdown
            cursor.execute(
                """
                SELECT 
                    CASE 
                        WHEN user_agent LIKE '%Mobile%' THEN 'mobile'
                        WHEN user_agent LIKE '%Tablet%' THEN 'tablet'
                        ELSE 'desktop'
                    END as device_type,
                    COUNT(*) as clicks
                FROM url_clicks 
                WHERE url_id = %s
                GROUP BY device_type
                """,
                (url_id,)
            )
            device_stats = cursor.fetchall()
            
            cursor.close()
            safe_close(conn)
            
            return {
                'url_info': url_info,
                'daily_clicks': daily_clicks,
                'location_stats': location_stats,
                'device_stats': device_stats,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Error getting URL performance metrics: {e}")
            return {'error': str(e)}

# =============================================================================
# URL Preview Feature
# =============================================================================

class URLPreviewManager:
    """Manages URL preview functionality"""
    
    @staticmethod
    def get_url_preview(url_id: str) -> Dict[str, Any]:
        """Get preview information for a URL"""
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                """
                SELECT u.id, u.code, u.original_url, u.clicks, u.created_at,
                       COUNT(uc.id) as total_clicks,
                       MAX(uc.clicked_at) as last_click
                FROM urls u
                LEFT JOIN url_clicks uc ON u.id = uc.url_id
                WHERE u.id = %s
                GROUP BY u.id
                """,
                (url_id,)
            )
            
            result = cursor.fetchone()
            
            cursor.close()
            safe_close(conn)
            
            if not result:
                return {'error': 'URL not found'}
            
            return {
                'id': result['id'],
                'code': result['code'],
                'original_url': result['original_url'],
                'total_clicks': result['total_clicks'],
                'created_at': result['created_at'].isoformat() if result['created_at'] else None,
                'last_click': result['last_click'].isoformat() if result['last_click'] else None,
                'short_url': f"http://localhost:5000/{result['code']}"
            }
            
        except Exception as e:
            logger.error(f"Error getting URL preview: {e}")
            return {'error': str(e)}

# =============================================================================
# Export managers for use in main app
# =============================================================================

url_expiration_manager = URLExpirationManager()
custom_domain_manager = CustomDomainManager()
bulk_url_manager = BulkURLManager()
url_analytics_manager = URLAnalyticsManager()
url_preview_manager = URLPreviewManager()
