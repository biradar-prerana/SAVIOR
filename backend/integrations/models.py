"""
Integrations models for third-party services
"""
from django.db import models
from django.conf import settings
from django.db import models

User = settings.AUTH_USER_MODEL


class Integration(models.Model):
    """Third-party service integration"""
    INTEGRATION_TYPES = [
        ('slack', 'Slack'),
        ('jira', 'JIRA'),
        ('servicenow', 'ServiceNow'),
        ('github', 'GitHub'),
        ('gitlab', 'GitLab'),
        ('azure_devops', 'Azure DevOps'),
        ('jenkins', 'Jenkins'),
        ('webhook', 'Webhook'),
        ('email', 'Email'),
        ('splunk', 'Splunk'),
        ('splunk_es', 'Splunk Enterprise Security'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    ]
    
    name = models.CharField(max_length=255)
    integration_type = models.CharField(max_length=50, choices=INTEGRATION_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    config = models.JSONField(default=dict)  # Integration-specific configuration
    credentials = models.JSONField(default=dict)  # Encrypted credentials
    is_enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_sync = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.integration_type})"


class IntegrationEvent(models.Model):
    """Events triggered by integrations"""
    EVENT_TYPES = [
        ('scan_started', 'Scan Started'),
        ('scan_completed', 'Scan Completed'),
        ('vulnerability_found', 'Vulnerability Found'),
        ('risk_assessment', 'Risk Assessment'),
        ('report_generated', 'Report Generated'),
    ]
    
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE, related_name='events')
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    payload = models.JSONField(default=dict)  # Event payload
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
    ], default='pending')
    sent_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.integration.name} - {self.event_type} ({self.status})"


class WebhookEndpoint(models.Model):
    """Webhook endpoint configuration"""
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE, related_name='webhooks')
    url = models.URLField()
    method = models.CharField(max_length=10, default='POST', choices=[
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
    ])
    headers = models.JSONField(default=dict)  # Custom headers
    secret = models.CharField(max_length=255, blank=True)  # Webhook secret for verification
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.integration.name} - {self.url}"

