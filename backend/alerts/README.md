# Alerts and Notifications Module

This module provides automated alert notifications for critical vulnerabilities via email, JIRA, and ServiceNow.

## Features

- **Email Alerts**: Automated email notifications for critical vulnerabilities
- **JIRA Integration**: Create JIRA tickets for vulnerabilities
- **ServiceNow Integration**: Create ServiceNow tickets for vulnerabilities
- **Alert Rules**: Configurable rules for automatic alert generation
- **Automatic Detection**: Alerts sent automatically when critical vulnerabilities are detected

## Alert Channels

### Email Alerts
- HTML email templates
- Includes vulnerability details, CVE ID, severity, AI risk score
- Remediation steps included
- Automatic sending on critical vulnerability detection

### JIRA Integration
- Creates JIRA tickets via REST API
- Includes all vulnerability details
- Links back to vulnerability in SAVIOR
- Configurable project, issue type, and priority

### ServiceNow Integration
- Creates ServiceNow incidents via REST API
- Includes vulnerability details
- Configurable urgency and impact
- Links back to vulnerability in SAVIOR

## Alert Rules

Alert rules define when and how alerts are sent:

- **Severity Threshold**: Minimum severity to trigger alert (critical, high, medium, low)
- **Risk Score Threshold**: Minimum AI risk score to trigger
- **CVE Required**: Only alert if CVE ID is present
- **Zero-Day Only**: Only alert for zero-day vulnerabilities
- **Channels**: Configure which channels to use (email, JIRA, ServiceNow)
- **Recipients**: Email addresses and users to notify

## Usage

### Create Alert Rule

```bash
POST /api/alerts/rules/
{
    "name": "Critical Vulnerability Alerts",
    "description": "Alert for all critical vulnerabilities",
    "severity_threshold": "critical",
    "send_email": true,
    "create_jira_ticket": true,
    "create_servicenow_ticket": false,
    "email_recipients": ["security@company.com", "admin@company.com"],
    "jira_integration": 1,
    "servicenow_integration": null
}
```

### Send Manual Alert

```bash
POST /api/alerts/alerts/send_alert/
{
    "vulnerability_id": 123,
    "alert_rule_id": 1
}
```

### Acknowledge Alert

```bash
POST /api/alerts/alerts/{id}/acknowledge/
```

### Test Alert Rule

```bash
POST /api/alerts/rules/{id}/test/
{
    "vulnerability_id": 123
}
```

## JIRA Configuration

### Create JIRA Integration

```bash
POST /api/integrations/integrations/
{
    "name": "JIRA Production",
    "integration_type": "jira",
    "config": {
        "base_url": "https://yourcompany.atlassian.net",
        "project_key": "SEC",
        "issue_type": "Bug",
        "priority": "Highest"
    },
    "credentials": {
        "username": "your-email@company.com",
        "api_token": "your-jira-api-token"
    }
}
```

### JIRA API Token
1. Go to JIRA → Account Settings → Security
2. Create API token
3. Use email as username and API token as password

## ServiceNow Configuration

### Create ServiceNow Integration

```bash
POST /api/integrations/integrations/
{
    "name": "ServiceNow Production",
    "integration_type": "servicenow",
    "config": {
        "instance_url": "https://yourcompany.service-now.com",
        "table_name": "incident"
    },
    "credentials": {
        "username": "your-username",
        "password": "your-password"
    }
}
```

## Email Configuration

Configure email settings in `.env`:

```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@savior.com
SITE_NAME=SAVIOR
```

### Gmail Setup
1. Enable 2-factor authentication
2. Generate App Password: Google Account → Security → App passwords
3. Use App Password as EMAIL_HOST_PASSWORD

## Automatic Alerts

Alerts are automatically sent when:
- A critical or high severity vulnerability is created
- The vulnerability meets the alert rule criteria
- Alert rules are active

This is handled by Django signals in `signals.py`.

## API Endpoints

- `GET /api/alerts/alerts/` - List all alerts
- `POST /api/alerts/alerts/send_alert/` - Manually send alert
- `POST /api/alerts/alerts/{id}/acknowledge/` - Acknowledge alert
- `GET /api/alerts/rules/` - List alert rules
- `POST /api/alerts/rules/` - Create alert rule
- `POST /api/alerts/rules/{id}/test/` - Test alert rule

## Email Templates

- `critical_vulnerability_email.html` - Email for critical vulnerabilities
- `vulnerability_summary_email.html` - Summary email for scan completion

## Example Alert Response

```json
{
    "id": 1,
    "alert_type": "critical_vulnerability",
    "status": "sent",
    "channel": "email",
    "vulnerability": 123,
    "title": "Critical Vulnerability: SQL Injection",
    "severity": "critical",
    "recipients": ["security@company.com"],
    "sent_at": "2024-01-15T10:30:00Z",
    "external_ticket_id": "SEC-123",
    "external_ticket_url": "https://jira.company.com/browse/SEC-123"
}
```

## Best Practices

1. **Configure Email**: Set up proper SMTP settings
2. **Test Integrations**: Use test endpoints to verify JIRA/ServiceNow connections
3. **Review Rules**: Regularly review and update alert rules
4. **Monitor Alerts**: Check alert status and acknowledge important alerts
5. **Limit Recipients**: Only include necessary recipients to avoid alert fatigue

