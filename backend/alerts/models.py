"""
Alert and notification models
"""
from django.db import models
from django.conf import settings
from django.db import models
from scanning.models import Vulnerability, Scan, ScanTarget

User = settings.AUTH_USER_MODEL


class Alert(models.Model):
    """Alert notification for critical vulnerabilities"""
    
    ALERT_TYPES = [
        ('critical_vulnerability', 'Critical Vulnerability'),
        ('high_vulnerability', 'High Vulnerability'),
        ('zero_day', 'Zero-Day Vulnerability'),
        ('anomaly', 'Anomaly Detected'),
        ('scan_completed', 'Scan Completed'),
        ('risk_threshold', 'Risk Threshold Exceeded'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('acknowledged', 'Acknowledged'),
    ]
    
    CHANNEL_CHOICES = [
        ('email', 'Email'),
        ('jira', 'JIRA'),
        ('servicenow', 'ServiceNow'),
        ('slack', 'Slack'),
        ('webhook', 'Webhook'),
    ]
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES)
    
    # Related entities
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE,
        related_name='alerts', null=True, blank=True
    )
    scan = models.ForeignKey(
        Scan, on_delete=models.CASCADE,
        related_name='alerts', null=True, blank=True
    )
    target = models.ForeignKey(
        ScanTarget, on_delete=models.CASCADE,
        related_name='alerts', null=True, blank=True
    )
    
    # Alert details
    title = models.CharField(max_length=500)
    message = models.TextField()
    severity = models.CharField(max_length=20, choices=Vulnerability.SEVERITY_CHOICES)
    
    # Recipients
    recipients = models.JSONField(default=list)  # List of email addresses or user IDs
    
    # Alert metadata
    alert_data = models.JSONField(default=dict)  # Additional alert data
    sent_at = models.DateTimeField(null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        related_name='acknowledged_alerts', null=True, blank=True
    )
    
    # Integration tracking
    integration = models.ForeignKey(
        'integrations.Integration', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='alerts'
    )
    external_ticket_id = models.CharField(max_length=255, blank=True)  # JIRA/ServiceNow ticket ID
    external_ticket_url = models.URLField(blank=True)  # Link to external ticket
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type', '-created_at']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['channel', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.channel}) - {self.status}"


class AlertRule(models.Model):
    """Rules for automatic alert generation"""
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    
    # Trigger conditions
    severity_threshold = models.CharField(
        max_length=20,
        choices=Vulnerability.SEVERITY_CHOICES,
        default='critical'
    )
    risk_score_threshold = models.FloatField(null=True, blank=True)  # Minimum risk score to trigger
    cve_required = models.BooleanField(default=False)  # Require CVE ID
    zero_day_only = models.BooleanField(default=False)  # Only zero-day vulnerabilities
    
    # Alert channels
    send_email = models.BooleanField(default=True)
    create_jira_ticket = models.BooleanField(default=False)
    create_servicenow_ticket = models.BooleanField(default=False)
    
    # Recipients
    email_recipients = models.JSONField(default=list)  # List of email addresses
    notify_users = models.ManyToManyField(User, blank=True, related_name='alert_rules')
    
    # Integration references
    jira_integration = models.ForeignKey(
        'integrations.Integration',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='jira_alert_rules',
        limit_choices_to={'integration_type': 'jira'}
    )
    servicenow_integration = models.ForeignKey(
        'integrations.Integration',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='servicenow_alert_rules',
        limit_choices_to={'integration_type': 'servicenow'}
    )
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_alert_rules')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({'Active' if self.is_active else 'Inactive'})"

