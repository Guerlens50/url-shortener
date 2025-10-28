import logging
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from typing import Optional, TypedDict, cast
import mysql.connector
import nanoid
from uuid import uuid4
from datetime import datetime, timedelta
from auth import hash_password, check_password, create_refresh_token, create_access_token, jwt_required,hash_token
import validators
from errors import handle_errors, APIError
from db import redis_client,get_connection,safe_close
from consts import RATE_LIMIT
from celery import Task
from typing import cast
from tasks import log_click,check_fraud
from prometheus_client import generate_latest,CONTENT_TYPE_LATEST
from metrics import REQUEST_COUNT,REQUEST_LATENCY
import time
import json
from fraud import get_fingerprint

# Import new modules
from api_docs import get_api_blueprint, get_namespaces
from health import health_check, health_check_lite, readiness_check, liveness_check
from validation import validate_signup_data, validate_shorten_request, ValidationError
from url_features import (
    url_expiration_manager, custom_domain_manager, bulk_url_manager,
    url_analytics_manager, url_preview_manager
)
from security import (
    setup_security_middleware, security_config, input_sanitizer,
    detect_attacks, sanitize_input, validate_content_type
)
    
log_click_task = cast(Task, log_click)
check_fraud_task=cast(Task,check_fraud)
# ---------------------------
# Logging setup
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)



# ---------------------------
# TypedDicts for MySQL rows
# ---------------------------
class UserRow(TypedDict):
    id: str
    username: str
    password_hash: str  # stored in DB


class URLRow(TypedDict):
    id: str
    code: str
    original_url: str
    clicks: int
    user_id: int

class URLClickRow(TypedDict):
    id:str
    url_id:str
    ip:str
    user_agent:str
    referrer:str
    clicked_at:str


# ---------------------------
# App + Config
# ---------------------------
app = Flask(__name__)

# Enable CORS for all routes
CORS(app, origins=security_config.CORS_ORIGINS, 
     methods=security_config.CORS_METHODS,
     allow_headers=security_config.CORS_HEADERS)

# Setup security middleware
setup_security_middleware(app)

# Register API documentation blueprint
api_bp = get_api_blueprint()
app.register_blueprint(api_bp)

# Get API namespaces for route registration
namespaces = get_namespaces()
auth_ns = namespaces['auth']
url_ns = namespaces['urls']
analytics_ns = namespaces['analytics']
admin_ns = namespaces['admin']


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()  # first IP is usually the client
    else:
        ip = request.remote_addr
    return ip

# ---------------------------
# Rate limiting helper
# ---------------------------
def check_rate_limit(user_id: str) -> bool:
    key = f"rate:{user_id}"
    current: Optional[int] = redis_client.get(key)  # type: ignore
    if current is None:
        redis_client.set(key, 1, ex=60)
        logger.info(f"Rate limit: new counter for user {user_id}")
        return True
    elif int(current) < RATE_LIMIT:
        redis_client.incr(key)
        logger.info(f"Rate limit: increment counter for user {user_id} ({int(current)+1})")
        return True
    logger.warning(f"Rate limit exceeded for user {user_id}")
    return False

def check_ip_rate_limit(ip: str) -> bool:
    key = f"rate_ip:{ip}"
    current: Optional[str] = redis_client.get(key)
    if current is None:
        redis_client.set(key, 1, ex=60)
        return True
    elif int(current) < RATE_LIMIT:  # <-- cast to int
        redis_client.incr(key)
        return True
    return False


# ---------------------------
# Measure start time
# ---------------------------
@app.before_request
def start_timer():
    request.environ["start_time"]= time.time()  # store start timestamp

# ---------------------------
# Record metrics after request
# ---------------------------
@app.after_request
def record_metrics(response):
    # Increment request count
    REQUEST_COUNT.labels(
        request.method, 
        request.path, 
        response.status_code
    ).inc()

    # Measure latency
    if hasattr(request, "start_time") and request.environ["start_time"] is not None:
        latency = time.time() - request.environ["start_time"]
        REQUEST_LATENCY.labels(request.path).observe(latency)
    return response

@app.route('/metrics')
def metrics():
    """ Exposes application metrics in a Prometheus-compatible format. """
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

# ---------------------------
# Health Check Routes
# ---------------------------
@app.route('/health')
def health_endpoint():
    """Comprehensive health check endpoint"""
    return health_check()

@app.route('/health/lite')
def health_lite_endpoint():
    """Lightweight health check for load balancers"""
    return health_check_lite()

@app.route('/ready')
def readiness_endpoint():
    """Readiness check for Kubernetes"""
    return readiness_check()

@app.route('/live')
def liveness_endpoint():
    """Liveness check for Kubernetes"""
    return liveness_check()

# ---------------------------
# Auth routes
# ---------------------------
@app.route("/auth/signup", methods=["POST"])
@handle_errors
@detect_attacks
@sanitize_input
@validate_content_type(['application/json'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    # Enhanced validation
    validation_result = validate_signup_data(data)
    if not validation_result['valid']:
        return jsonify({
            "error": "Validation failed",
            "details": validation_result['errors'],
            "warnings": validation_result['warnings']
        }), 400
    
    username: str = data["username"]
    password: str = data["password"]

    pw_hash = hash_password(password)
    conn=get_connection()
    cursor= conn.cursor(dictionary=True)
    try:    
        cursor.execute(
            "INSERT INTO users (id, username, password_hash) VALUES (%s, %s, %s)",
            (str(uuid4()), username, pw_hash),
        )
        conn.commit()
        logger.info(f"User created: {username}")
        return jsonify({"msg": "User created"}), 201
    except mysql.connector.errors.IntegrityError:
        logger.warning(f"Signup failed: Username {username} already exists")
        return jsonify({"msg": "Username already exists"}), 400
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        safe_close(conn)


@app.route("/auth/login", methods=["POST"])
@handle_errors
def login():
    data = request.get_json()
    username: str = data["username"]
    password: str = data["password"]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch user
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        row = cast(Optional[UserRow], cursor.fetchone())

        if not row or not check_password(password, row["password_hash"]):
            logger.warning(f"Login failed for username: {username}")
            return jsonify({"msg": "Bad credentials"}), 401

        # Generate tokens
        access_token = create_access_token(row["id"])
        jti=str(uuid4())
        refresh_token = create_refresh_token(row["id"],jti)
        hashed_token = hash_token(refresh_token)

        # Store refresh token in DB (hashed)
        cursor.execute(
            """
            INSERT INTO refresh_tokens (id, token_hash, user_id, expires_at)
            VALUES (%s, %s, %s, DATE_ADD(NOW(), INTERVAL 30 DAY))
            """,
            (jti, hashed_token, row["id"])
        )
        conn.commit()
        logger.info(f"User logged in: {username}")
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    finally:
        cursor.close()
        safe_close(conn)


@app.route("/auth/access_token", methods=["POST"])
@jwt_required(token_type="refresh")
def access_token():
    user_id = request.environ["user_id"]
    token = create_access_token(user_id)
    logger.info(f"Issued access token for user_id: {user_id}")
    return jsonify({"access_token": token})

@app.route("/auth/logout", methods=["POST"])
@jwt_required(token_type="refresh")  # Only refresh token can be revoked
@handle_errors
def logout():
    payload=request.environ["claims"]
    user_id=request.environ["user_id"]
    jti = payload.get("jti",None)
    if not jti:
        return jsonify({"error": "Invalid token"}), 401

    # Delete refresh token from DB
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM refresh_tokens WHERE id=%s AND user_id=%s",
            (jti, user_id)
        )
        conn.commit()
        logger.info(f"User {user_id} logged out, revoked refresh token {jti}")
    finally:
        cursor.close()
        safe_close(conn)

    return jsonify({"msg": "Logged out successfully"}), 200


# ---------------------------
# URL Shortener routes
# ---------------------------
@app.route("/shorten", methods=["POST"])
@jwt_required(token_type="access")
@handle_errors
@detect_attacks
@sanitize_input
@validate_content_type(['application/json'])
def shorten_url():
    user_id: str = request.environ["user_id"]
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    # Enhanced validation
    validation_result = validate_shorten_request(data)
    if not validation_result['valid']:
        return jsonify({
            "error": "Validation failed",
            "details": validation_result['errors'],
            "warnings": validation_result['warnings']
        }), 400
    
    # Use sanitized URL from validation
    original_url: str = validation_result['sanitized_data']['url']
    code: str = data.get("code")
    
    ip_addr=get_client_ip()
    if ip_addr is None:
        return jsonify({"error": "Unable to determine client IP"}), 400
    
    if not check_rate_limit(user_id) or not check_ip_rate_limit(ip_addr):
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return jsonify({"error": f"Rate limit exceeded: {RATE_LIMIT} requests per minute"}), 429

    if not code:
        code = nanoid.generate(size=8)
    
    conn=get_connection()
    cursor= conn.cursor(dictionary=True)    
    try:
        cursor.execute(
            "INSERT INTO urls (id, code, original_url, user_id) VALUES (%s, %s, %s, %s)",
            (str(uuid4()), code, original_url, user_id),
        )
        conn.commit()
        redis_client.set(code, original_url, ex=86400)  # cache 1 day
        logger.info(f"URL shortened by user {user_id}: {original_url} -> {code}")

        return jsonify({
            "short_url": f"http://localhost:5000/{code}",
            "code": code,
            "original_url": original_url
        })
    except mysql.connector.errors.IntegrityError as e:
        logger.warning(f"Short code conflict: {code}")
        return jsonify({"error": "Short code already exists"}), 409
    except Exception as e:
        logger.error(f"URL shortening error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        safe_close(conn)


@app.route("/<code>")
@handle_errors
def redirect_url(code: str):
    # Try Redis first
    original_url = redis_client.get(code)
    url_id = None
    # Always query DB if Redis misses
    conn=get_connection()
    cursor= conn.cursor(dictionary=True)
  
    if not original_url:
        cursor.execute("SELECT * FROM urls WHERE code=%s", (code,))
        row = cursor.fetchone()
        if not row:
            logger.warning(f"Redirect failed, code not found: {code}")
            return "URL not found", 404
        original_url = row["original_url"] # pyright: ignore[reportArgumentType, reportCallIssue]
        url_id = row["id"] # pyright: ignore[reportArgumentType, reportCallIssue]
        redis_client.set(code, original_url, ex=86400) # pyright: ignore[reportArgumentType]
    else:
        # Even if cached, get url_id from DB
        cursor.execute("SELECT id, code FROM urls WHERE code=%s", (code,))
        row = cursor.fetchone()
        url_id = row["id"] if row else None # type: ignore
        url_code = row["code"] if row else code #type: ignore
    if not url_id:
        logger.warning(f"Redirect failed, URL ID not found in DB: {code}")
        return "URL not found", 404
    fingerprint = get_fingerprint()
    log_click_task.delay(url_id, get_client_ip(), request.headers.get("User-Agent"), request.referrer, fingerprint)
    check_fraud_task.delay(get_client_ip(), url_code, request.headers.get("User-Agent"), request.referrer, fingerprint) # type: ignore# type: ignore
    cursor.close()
    safe_close(conn)
    logger.info(f"URL clicked: {code} by IP {request.remote_addr}")

    return redirect(original_url) # type: ignore



# ---------------------------
# Protected analytics
# ---------------------------
@app.route("/stats/<code>")
@jwt_required(token_type="access")
@handle_errors
def stats(code: str):
    user_id: str = request.environ["user_id"]
    ip_addr=get_client_ip()
    if ip_addr is None:
        return jsonify({}),429
    if not check_rate_limit(user_id) or not check_ip_rate_limit(ip_addr):
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return jsonify({"error": f"Rate limit exceeded: {RATE_LIMIT} requests per minute"}), 429
    conn=get_connection()
    cursor= conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM urls WHERE code=%s", (code,))
    row = cast(Optional[URLRow], cursor.fetchone())
    cursor.close()
    safe_close(conn)
    if not row or row["user_id"] != user_id:
        logger.warning(f"Stats access unauthorized for user {user_id}, code {code}")
        return jsonify({"msg": "Not found or unauthorized"}), 404
    logger.info(f"Stats retrieved for user {user_id}, code {code}")
    return jsonify({
        "original_url": row["original_url"],
        "clicks": row["clicks"],
    })

@app.route("/analytics/<code>", methods=["GET"])
@jwt_required(token_type="access")
@handle_errors
def analytics(code: str):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get URL info
    cursor.execute("SELECT id FROM urls WHERE code=%s", (code,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"msg": "URL not found"}), 404
    url_id = row["id"]

    # Fetch hourly analytics
    cursor.execute("""
        SELECT DATE_FORMAT(date_hour, '%%Y-%%m-%%d %%H:00') as hour, clicks, unique_visitors, suspicious_clicks
        FROM url_analytics_hourly
        WHERE url_id=%s
        ORDER BY date_hour ASC
    """, (url_id,))
    hourly_data = cursor.fetchall()

    # Fetch top referrers
    cursor.execute("""
        SELECT referrer, clicks
        FROM url_referrers
        WHERE url_id=%s
        ORDER BY clicks DESC
        LIMIT 10
    """, (url_id,))
    top_referrers = cursor.fetchall()
    
    cursor.close()
    safe_close(conn)
    return jsonify({
        "hourly": hourly_data,
        "top_referrers": top_referrers
    })


@app.route("/trending_urls", methods=["GET"])
@jwt_required(token_type="access")
def get_trendings():
    trending_json = redis_client.get("trending_urls")  # type: ignore
    if not trending_json:
        return jsonify([]), 200
    return jsonify(json.loads(trending_json)), 200  # type: ignore

# ---------------------------
# Enhanced URL Features
# ---------------------------

@app.route("/urls/<url_id>/expire", methods=["POST"])
@jwt_required(token_type="access")
@handle_errors
def set_url_expiration(url_id: str):
    """Set expiration date for a URL"""
    user_id: str = request.environ["user_id"]
    data = request.get_json()
    
    if not data or 'expires_in_hours' not in data:
        return jsonify({"error": "expires_in_hours is required"}), 400
    
    expires_in_hours = data['expires_in_hours']
    if not isinstance(expires_in_hours, (int, float)) or expires_in_hours <= 0:
        return jsonify({"error": "expires_in_hours must be a positive number"}), 400
    
    # Check if user owns the URL
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM urls WHERE id = %s", (url_id,))
        url_row = cursor.fetchone()
        
        if not url_row or url_row['user_id'] != user_id:
            return jsonify({"error": "URL not found or unauthorized"}), 404
        
        # Set expiration
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        success = url_expiration_manager.add_expiration_to_url(url_id, expires_at)
        
        if success:
            return jsonify({
                "message": "Expiration set successfully",
                "expires_at": expires_at.isoformat()
            })
        else:
            return jsonify({"error": "Failed to set expiration"}), 500
            
    finally:
        cursor.close()
        safe_close(conn)

@app.route("/urls/bulk", methods=["POST"])
@jwt_required(token_type="access")
@handle_errors
def bulk_shorten_urls():
    """Shorten multiple URLs in a single request"""
    user_id: str = request.environ["user_id"]
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({"error": "urls array is required"}), 400
    
    urls = data['urls']
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "urls must be a non-empty array"}), 400
    
    result = bulk_url_manager.bulk_shorten_urls(urls, user_id)
    
    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@app.route("/urls/<url_id>/preview", methods=["GET"])
@jwt_required(token_type="access")
@handle_errors
def get_url_preview(url_id: str):
    """Get preview information for a URL"""
    user_id: str = request.environ["user_id"]
    
    # Check if user owns the URL
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM urls WHERE id = %s", (url_id,))
        url_row = cursor.fetchone()
        
        if not url_row or url_row['user_id'] != user_id:
            return jsonify({"error": "URL not found or unauthorized"}), 404
        
        preview = url_preview_manager.get_url_preview(url_id)
        
        if 'error' in preview:
            return jsonify(preview), 404
        
        return jsonify(preview)
        
    finally:
        cursor.close()
        safe_close(conn)

@app.route("/urls/<url_id>/performance", methods=["GET"])
@jwt_required(token_type="access")
@handle_errors
def get_url_performance(url_id: str):
    """Get performance metrics for a URL"""
    user_id: str = request.environ["user_id"]
    days = request.args.get('days', 30, type=int)
    
    # Check if user owns the URL
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM urls WHERE id = %s", (url_id,))
        url_row = cursor.fetchone()
        
        if not url_row or url_row['user_id'] != user_id:
            return jsonify({"error": "URL not found or unauthorized"}), 404
        
        metrics = url_analytics_manager.get_url_performance_metrics(url_id, days)
        
        if 'error' in metrics:
            return jsonify(metrics), 500
        
        return jsonify(metrics)
        
    finally:
        cursor.close()
        safe_close(conn)

@app.route("/urls/<url_id>/delete", methods=["DELETE"])
@jwt_required(token_type="access")
@handle_errors
def delete_url(url_id: str):
    """Delete a URL"""
    user_id: str = request.environ["user_id"]
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Check if user owns the URL
        cursor.execute("SELECT user_id, code FROM urls WHERE id = %s", (url_id,))
        url_row = cursor.fetchone()
        
        if not url_row or url_row['user_id'] != user_id:
            return jsonify({"error": "URL not found or unauthorized"}), 404
        
        # Delete the URL (cascade will handle related records)
        cursor.execute("DELETE FROM urls WHERE id = %s", (url_id,))
        conn.commit()
        
        # Remove from Redis cache
        redis_client.delete(url_row['code'])
        
        logger.info(f"URL {url_id} deleted by user {user_id}")
        return jsonify({"message": "URL deleted successfully"})
        
    finally:
        cursor.close()
        safe_close(conn)



# ---------------------------
# Entry
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)