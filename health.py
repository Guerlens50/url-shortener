"""
Health Check and System Status Module
Provides health check endpoints and system monitoring capabilities
"""

import time
import psutil
import platform
from datetime import datetime
from flask import jsonify, request
from db import get_connection, redis_client, safe_close
import mysql.connector
import redis
import logging

logger = logging.getLogger(__name__)

class HealthChecker:
    """Health check service for monitoring system status"""
    
    def __init__(self):
        self.start_time = time.time()
        self.version = "1.0.0"
    
    def check_database(self):
        """Check database connectivity and performance"""
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Test basic connectivity
            start_time = time.time()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            db_latency = time.time() - start_time
            
            # Check database size
            cursor.execute("SELECT COUNT(*) FROM urls")
            url_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.close()
            safe_close(conn)
            
            return {
                "status": "healthy",
                "latency_ms": round(db_latency * 1000, 2),
                "url_count": url_count,
                "user_count": user_count
            }
        except mysql.connector.Error as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"Database health check error: {e}")
            return {
                "status": "unhealthy",
                "error": "Connection failed"
            }
    
    def check_redis(self):
        """Check Redis connectivity and performance"""
        try:
            # Test basic connectivity
            start_time = time.time()
            redis_client.ping()
            redis_latency = time.time() - start_time
            
            # Get Redis info
            info = redis_client.info()
            
            return {
                "status": "healthy",
                "latency_ms": round(redis_latency * 1000, 2),
                "memory_used": info.get('used_memory_human', 'unknown'),
                "connected_clients": info.get('connected_clients', 0),
                "keyspace_hits": info.get('keyspace_hits', 0),
                "keyspace_misses": info.get('keyspace_misses', 0)
            }
        except redis.RedisError as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"Redis health check error: {e}")
            return {
                "status": "unhealthy",
                "error": "Connection failed"
            }
    
    def check_system_resources(self):
        """Check system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "cpu_percent": cpu_percent,
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                }
            }
        except Exception as e:
            logger.error(f"System resources check failed: {e}")
            return {
                "error": str(e)
            }
    
    def get_system_info(self):
        """Get system information"""
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "uptime_seconds": time.time() - self.start_time
        }
    
    def comprehensive_health_check(self):
        """Perform comprehensive health check"""
        db_status = self.check_database()
        redis_status = self.check_redis()
        system_resources = self.check_system_resources()
        system_info = self.get_system_info()
        
        # Determine overall health
        overall_status = "healthy"
        if db_status["status"] != "healthy" or redis_status["status"] != "healthy":
            overall_status = "unhealthy"
        
        return {
            "status": overall_status,
            "version": self.version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "services": {
                "database": db_status,
                "redis": redis_status
            },
            "system": {
                "resources": system_resources,
                "info": system_info
            }
        }

# Global health checker instance
health_checker = HealthChecker()

def health_check():
    """Basic health check endpoint"""
    return jsonify(health_checker.comprehensive_health_check())

def health_check_lite():
    """Lightweight health check for load balancers"""
    try:
        # Quick database ping
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        safe_close(conn)
        
        # Quick Redis ping
        redis_client.ping()
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 503

def readiness_check():
    """Readiness check for Kubernetes"""
    try:
        # Check if all services are ready
        db_status = health_checker.check_database()
        redis_status = health_checker.check_redis()
        
        if db_status["status"] == "healthy" and redis_status["status"] == "healthy":
            return jsonify({
                "status": "ready",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        else:
            return jsonify({
                "status": "not_ready",
                "services": {
                    "database": db_status["status"],
                    "redis": redis_status["status"]
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }), 503
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return jsonify({
            "status": "not_ready",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 503

def liveness_check():
    """Liveness check for Kubernetes"""
    return jsonify({
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_seconds": time.time() - health_checker.start_time
    })

# Metrics for health checks
def get_health_metrics():
    """Get health-related metrics"""
    try:
        db_status = health_checker.check_database()
        redis_status = health_checker.check_redis()
        system_resources = health_checker.check_system_resources()
        
        return {
            "database_latency_ms": db_status.get("latency_ms", 0),
            "redis_latency_ms": redis_status.get("latency_ms", 0),
            "cpu_percent": system_resources.get("cpu_percent", 0),
            "memory_percent": system_resources.get("memory", {}).get("percent", 0),
            "disk_percent": system_resources.get("disk", {}).get("percent", 0)
        }
    except Exception as e:
        logger.error(f"Failed to get health metrics: {e}")
        return {}
