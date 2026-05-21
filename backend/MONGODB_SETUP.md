# MongoDB Setup and Configuration Guide

## Overview

SAVIOR uses MongoDB for storing vulnerability scan results, CVE data, AI risk scores, and scan history. The connection is configured with secure handling including SSL/TLS support, connection pooling, and authentication.

## Configuration

### Basic Configuration

Edit `backend/.env` file with your MongoDB settings:

```env
MONGODB_NAME=savior_db
MONGODB_HOST=mongodb://localhost:27017/
MONGODB_USER=your_username
MONGODB_PASSWORD=your_password
MONGODB_AUTH_SOURCE=admin
MONGODB_AUTH_MECHANISM=SCRAM-SHA-1
```

### Secure Connection (Production)

For production environments, enable SSL/TLS:

```env
MONGODB_SSL=True
MONGODB_SSL_CERT_REQS=CERT_REQUIRED
MONGODB_SSL_CA_CERTS=/path/to/ca-cert.pem
MONGODB_SSL_CERTFILE=/path/to/client-cert.pem
MONGODB_SSL_KEYFILE=/path/to/client-key.pem
```

### Connection Pool Settings

Optimize connection pool for your workload:

```env
MONGODB_MAX_POOL_SIZE=50
MONGODB_MIN_POOL_SIZE=10
MONGODB_MAX_IDLE_TIME_MS=45000
MONGODB_CONNECT_TIMEOUT_MS=20000
MONGODB_SERVER_SELECTION_TIMEOUT_MS=5000
MONGODB_RETRY_WRITES=True
MONGODB_RETRY_READS=True
```

## Data Models

### Vulnerability Scan Results

Stored in `scanning_scan` collection:
- Scan configuration and status
- Scan results and summary statistics
- Vulnerability counts by severity
- Scan execution metadata

### CVE Data

Stored in `scanning_cvedata` collection:
- CVE identifiers and descriptions
- CVSS v2, v3, and v3.1 scores
- Affected products and CPE lists
- References and vendor advisories
- Exploit availability information

### AI Risk Scores

Stored in `ai_risk_scoring_riskscore` collection:
- Overall risk scores
- Exploitability and impact scores
- AI model analysis and factors
- Remediation priority rankings

### Scan History

All scans are tracked with:
- Timestamps (started_at, completed_at)
- Status changes
- User who initiated the scan
- Complete scan configuration

## Indexes

Create optimized indexes for performance:

```bash
python manage.py create_mongodb_indexes
```

This creates indexes on:
- Scan: target, status, user, dates
- Vulnerability: scan, severity, CVE ID, false positives
- CVE: CVE ID, severity, CVSS scores, dates

## Usage

### Direct MongoDB Access

```python
from savior_backend.mongodb import mongodb_connection

# Get database
db = mongodb_connection.get_database()

# Get collection
collection = mongodb_connection.get_collection('scanning_scan')

# Query
scans = collection.find({'status': 'completed'})
```

### Using Django Models

```python
from scanning.models import Scan, Vulnerability
from scanning.cve_models import CVEData

# Create scan
scan = Scan.objects.create(
    target=target,
    scan_type='web',
    initiated_by=user
)

# Create vulnerability
vuln = Vulnerability.objects.create(
    scan=scan,
    title='SQL Injection',
    severity='high',
    cve_id='CVE-2023-1234'
)

# Link CVE data
from scanning.cve_utils import link_vulnerability_to_cve
link_vulnerability_to_cve(vuln)
```

## Security Best Practices

1. **Always use authentication** in production
2. **Enable SSL/TLS** for encrypted connections
3. **Use strong passwords** for MongoDB users
4. **Restrict network access** to MongoDB server
5. **Regular backups** of MongoDB data
6. **Monitor connection logs** for suspicious activity

## Troubleshooting

### Connection Issues

1. Verify MongoDB is running:
   ```bash
   mongosh --eval "db.adminCommand('ping')"
   ```

2. Check connection string format:
   - Local: `mongodb://localhost:27017/`
   - Remote: `mongodb://user:pass@host:port/`

3. Verify authentication credentials

### SSL/TLS Issues

1. Ensure certificate files are accessible
2. Check certificate permissions
3. Verify SSL certificate requirements match your setup

### Performance Issues

1. Create indexes: `python manage.py create_mongodb_indexes`
2. Monitor connection pool usage
3. Check query performance with MongoDB explain plans

## Backup and Recovery

### Backup

```bash
mongodump --db savior_db --out /backup/path
```

### Restore

```bash
mongorestore --db savior_db /backup/path/savior_db
```

## Monitoring

Monitor MongoDB metrics:
- Connection pool usage
- Query performance
- Index usage
- Storage size
- Replication lag (if using replica sets)

