# 🚀 Deployment Guide - URL Shortener Service

This guide provides comprehensive instructions for deploying the Enhanced URL Shortener service in various environments.

## 📋 Prerequisites

- Python 3.11+
- MySQL 8.0+
- Redis 6.0+
- Docker & Docker Compose (optional)
- SSL certificates (for production)

## 🐳 Docker Deployment (Recommended)

### Quick Start with Docker Compose

1. **Clone the repository**
```bash
git clone https://github.com/Guerlens50/url-shortener.git
cd url-shortener
```

2. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start all services**
```bash
docker-compose up -d
```

4. **Verify deployment**
```bash
# Check service status
docker-compose ps

# Check logs
docker-compose logs -f app

# Test health endpoint
curl http://localhost:5000/health
```

### Docker Compose Configuration

The `docker-compose.yml` includes:
- **app**: Main Flask application
- **db**: MySQL database
- **redis**: Redis cache
- **celery-worker**: Background task processor
- **celery-beat**: Scheduled task scheduler
- **prometheus**: Metrics collection
- **grafana**: Metrics visualization

### Environment Variables for Docker

Create a `.env` file:

```env
# Application
FLASK_ENV=production
FLASK_DEBUG=false

# Database
MYSQL_HOST=db
MYSQL_USER=root
MYSQL_PASSWORD=secure_password
MYSQL_DB=urlshortener

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# JWT
JWT_PRIVATE_KEY=/app/keys/private.pem
JWT_PUBLIC_KEY=/app/keys/public.pem
JWT_ISSUER=your-domain.com
JWT_AUDIENCE=your-domain.com

# Security
CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com
ENABLE_HTTPS_REDIRECT=true
MAX_REQUEST_SIZE=16777216

# Rate Limiting
RATE_LIMIT=100
MAX_CLICKS_PER_MINUTE_PER_IP=50

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
```

## ☁️ Cloud Deployment

### AWS Deployment

#### Using AWS ECS with Fargate

1. **Create ECS Cluster**
```bash
aws ecs create-cluster --cluster-name url-shortener
```

2. **Create Task Definition**
```json
{
  "family": "url-shortener",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "url-shortener-app",
      "image": "your-account.dkr.ecr.region.amazonaws.com/url-shortener:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "FLASK_ENV", "value": "production"},
        {"name": "MYSQL_HOST", "value": "your-rds-endpoint"},
        {"name": "REDIS_HOST", "value": "your-elasticache-endpoint"}
      ],
      "secrets": [
        {
          "name": "MYSQL_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:mysql-password"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/url-shortener",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

3. **Create Service**
```bash
aws ecs create-service \
  --cluster url-shortener \
  --service-name url-shortener-service \
  --task-definition url-shortener:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345],assignPublicIp=ENABLED}"
```

#### Using AWS RDS for MySQL

```bash
aws rds create-db-instance \
  --db-instance-identifier url-shortener-db \
  --db-instance-class db.t3.micro \
  --engine mysql \
  --engine-version 8.0.35 \
  --master-username admin \
  --master-user-password your-secure-password \
  --allocated-storage 20 \
  --vpc-security-group-ids sg-12345 \
  --db-subnet-group-name your-subnet-group
```

#### Using AWS ElastiCache for Redis

```bash
aws elasticache create-cache-cluster \
  --cache-cluster-id url-shortener-redis \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --num-cache-nodes 1 \
  --security-group-ids sg-12345
```

### Google Cloud Platform Deployment

#### Using Google Cloud Run

1. **Build and push image**
```bash
gcloud builds submit --tag gcr.io/PROJECT-ID/url-shortener
```

2. **Deploy to Cloud Run**
```bash
gcloud run deploy url-shortener \
  --image gcr.io/PROJECT-ID/url-shortener \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars FLASK_ENV=production,MYSQL_HOST=your-cloud-sql-ip
```

#### Using Google Cloud SQL

```bash
gcloud sql instances create url-shortener-db \
  --database-version=MYSQL_8_0 \
  --tier=db-f1-micro \
  --region=us-central1 \
  --root-password=your-secure-password
```

### Azure Deployment

#### Using Azure Container Instances

```bash
az container create \
  --resource-group myResourceGroup \
  --name url-shortener \
  --image your-registry.azurecr.io/url-shortener:latest \
  --cpu 1 \
  --memory 1 \
  --ports 5000 \
  --environment-variables FLASK_ENV=production MYSQL_HOST=your-mysql-server.mysql.database.azure.com
```

## 🏗️ Manual Deployment

### 1. Server Setup

#### Ubuntu/Debian

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11
sudo apt install python3.11 python3.11-pip python3.11-venv -y

# Install MySQL
sudo apt install mysql-server -y

# Install Redis
sudo apt install redis-server -y

# Install Nginx
sudo apt install nginx -y

# Install Certbot for SSL
sudo apt install certbot python3-certbot-nginx -y
```

#### CentOS/RHEL

```bash
# Update system
sudo yum update -y

# Install Python 3.11
sudo yum install python311 python311-pip -y

# Install MySQL
sudo yum install mysql-server -y

# Install Redis
sudo yum install redis -y

# Install Nginx
sudo yum install nginx -y
```

### 2. Application Deployment

```bash
# Clone repository
git clone https://github.com/Guerlens50/url-shortener.git
cd url-shortener

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create application user
sudo useradd -m -s /bin/bash urlshortener
sudo chown -R urlshortener:urlshortener /path/to/url-shortener
```

### 3. Database Setup

```bash
# Start MySQL
sudo systemctl start mysql
sudo systemctl enable mysql

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -u root -p
```

```sql
CREATE DATABASE urlshortener;
CREATE USER 'urlshortener'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON urlshortener.* TO 'urlshortener'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

```bash
# Import schema
mysql -u urlshortener -p urlshortener < sql/schema.sql
```

### 4. Redis Setup

```bash
# Start Redis
sudo systemctl start redis
sudo systemctl enable redis

# Configure Redis
sudo nano /etc/redis/redis.conf
```

Add/modify these settings:
```
bind 127.0.0.1
port 6379
requirepass your_redis_password
maxmemory 256mb
maxmemory-policy allkeys-lru
```

### 5. Application Configuration

Create `/etc/url-shortener/config.env`:

```env
# Application
FLASK_ENV=production
FLASK_DEBUG=false

# Database
MYSQL_HOST=localhost
MYSQL_USER=urlshortener
MYSQL_PASSWORD=secure_password
MYSQL_DB=urlshortener

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# JWT
JWT_PRIVATE_KEY=/etc/url-shortener/keys/private.pem
JWT_PUBLIC_KEY=/etc/url-shortener/keys/public.pem
JWT_ISSUER=your-domain.com
JWT_AUDIENCE=your-domain.com

# Security
CORS_ORIGINS=https://your-domain.com
ENABLE_HTTPS_REDIRECT=true
```

### 6. Systemd Service Configuration

Create `/etc/systemd/system/url-shortener.service`:

```ini
[Unit]
Description=URL Shortener Service
After=network.target mysql.service redis.service

[Service]
Type=simple
User=urlshortener
Group=urlshortener
WorkingDirectory=/path/to/url-shortener
Environment=PATH=/path/to/url-shortener/venv/bin
ExecStart=/path/to/url-shortener/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/url-shortener-celery.service`:

```ini
[Unit]
Description=URL Shortener Celery Worker
After=network.target mysql.service redis.service

[Service]
Type=simple
User=urlshortener
Group=urlshortener
WorkingDirectory=/path/to/url-shortener
Environment=PATH=/path/to/url-shortener/venv/bin
ExecStart=/path/to/url-shortener/venv/bin/celery -A tasks worker --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 7. Nginx Configuration

Create `/etc/nginx/sites-available/url-shortener`:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Static files
    location /static {
        alias /path/to/url-shortener/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Health checks
    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/url-shortener /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 8. SSL Certificate

```bash
# Get SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

### 9. Start Services

```bash
# Start application services
sudo systemctl start url-shortener
sudo systemctl start url-shortener-celery
sudo systemctl enable url-shortener
sudo systemctl enable url-shortener-celery

# Check status
sudo systemctl status url-shortener
sudo systemctl status url-shortener-celery
```

## 📊 Monitoring & Logging

### Application Logs

```bash
# View application logs
sudo journalctl -u url-shortener -f

# View Celery logs
sudo journalctl -u url-shortener-celery -f

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Health Monitoring

Set up monitoring for these endpoints:
- `GET /health` - Comprehensive health check
- `GET /health/lite` - Lightweight health check
- `GET /ready` - Readiness probe
- `GET /live` - Liveness probe
- `GET /metrics` - Prometheus metrics

### Prometheus Configuration

Create `/etc/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'url-shortener'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

## 🔧 Maintenance

### Database Maintenance

```bash
# Backup database
mysqldump -u urlshortener -p urlshortener > backup_$(date +%Y%m%d).sql

# Optimize database
mysql -u urlshortener -p urlshortener -e "OPTIMIZE TABLE urls, url_clicks, users;"

# Clean old data
mysql -u urlshortener -p urlshortener -e "DELETE FROM url_clicks WHERE clicked_at < DATE_SUB(NOW(), INTERVAL 90 DAY);"
```

### Redis Maintenance

```bash
# Monitor Redis memory
redis-cli info memory

# Clear expired keys
redis-cli --scan --pattern "rate:*" | xargs redis-cli del

# Monitor Redis performance
redis-cli monitor
```

### Application Updates

```bash
# Stop services
sudo systemctl stop url-shortener url-shortener-celery

# Backup current version
cp -r /path/to/url-shortener /path/to/url-shortener.backup

# Pull updates
cd /path/to/url-shortener
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run database migrations (if any)
mysql -u urlshortener -p urlshortener < sql/migrations/latest.sql

# Restart services
sudo systemctl start url-shortener url-shortener-celery
```

## 🚨 Troubleshooting

### Common Issues

1. **Service won't start**
   - Check logs: `sudo journalctl -u url-shortener -n 50`
   - Verify configuration files
   - Check database connectivity

2. **Database connection errors**
   - Verify MySQL is running: `sudo systemctl status mysql`
   - Check credentials in config
   - Test connection: `mysql -u urlshortener -p urlshortener`

3. **Redis connection errors**
   - Verify Redis is running: `sudo systemctl status redis`
   - Check Redis configuration
   - Test connection: `redis-cli ping`

4. **High memory usage**
   - Monitor Redis memory usage
   - Check for memory leaks in application
   - Optimize database queries

5. **SSL certificate issues**
   - Check certificate validity: `sudo certbot certificates`
   - Renew if needed: `sudo certbot renew`
   - Verify Nginx configuration

### Performance Optimization

1. **Database Optimization**
   - Add appropriate indexes
   - Optimize slow queries
   - Use connection pooling

2. **Redis Optimization**
   - Configure appropriate memory limits
   - Use Redis clustering for high availability
   - Monitor key expiration

3. **Application Optimization**
   - Use gunicorn with multiple workers
   - Enable application-level caching
   - Optimize static file serving

## 📈 Scaling

### Horizontal Scaling

1. **Load Balancer Configuration**
   - Use Nginx or HAProxy as load balancer
   - Configure health checks
   - Implement session affinity if needed

2. **Database Scaling**
   - Use read replicas for analytics queries
   - Implement database sharding
   - Use connection pooling

3. **Redis Scaling**
   - Use Redis Cluster for high availability
   - Implement Redis Sentinel for failover
   - Use Redis replication for read scaling

### Vertical Scaling

1. **Increase Server Resources**
   - Add more CPU cores
   - Increase RAM
   - Use faster storage (SSD)

2. **Optimize Application**
   - Use async processing
   - Implement caching strategies
   - Optimize database queries

---

This deployment guide provides comprehensive instructions for deploying the URL Shortener service in various environments. Choose the deployment method that best fits your needs and infrastructure requirements.
