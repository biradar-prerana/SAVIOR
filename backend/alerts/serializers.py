"""
Serializers for alerts module
"""
from rest_framework import serializers
from .models import Alert, AlertRule
from scanning.serializers import VulnerabilitySerializer, ScanSerializer, ScanTargetSerializer
from integrations.serializers import IntegrationSerializer


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert"""
    vulnerability_data = VulnerabilitySerializer(source='vulnerability', read_only=True)
    scan_data = ScanSerializer(source='scan', read_only=True)
    target_data = ScanTargetSerializer(source='target', read_only=True)
    acknowledged_by_username = serializers.CharField(source='acknowledged_by.username', read_only=True)
    integration_data = IntegrationSerializer(source='integration', read_only=True)
    
    class Meta:
        model = Alert
        fields = [
            'id', 'alert_type', 'status', 'channel', 'vulnerability', 'vulnerability_data',
            'scan', 'scan_data', 'target', 'target_data', 'title', 'message', 'severity',
            'recipients', 'alert_data', 'sent_at', 'acknowledged_at', 'acknowledged_by',
            'acknowledged_by_username', 'integration', 'integration_data',
            'external_ticket_id', 'external_ticket_url', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class AlertRuleSerializer(serializers.ModelSerializer):
    """Serializer for AlertRule"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    notify_users_usernames = serializers.SerializerMethodField()
    jira_integration_name = serializers.CharField(source='jira_integration.name', read_only=True)
    servicenow_integration_name = serializers.CharField(source='servicenow_integration.name', read_only=True)
    
    class Meta:
        model = AlertRule
        fields = [
            'id', 'name', 'description', 'is_active', 'severity_threshold',
            'risk_score_threshold', 'cve_required', 'zero_day_only',
            'send_email', 'create_jira_ticket', 'create_servicenow_ticket',
            'email_recipients', 'notify_users', 'notify_users_usernames',
            'jira_integration', 'jira_integration_name',
            'servicenow_integration', 'servicenow_integration_name',
            'created_by', 'created_by_username', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_by', 'created_at', 'updated_at']
    
    def get_notify_users_usernames(self, obj):
        return [user.username for user in obj.notify_users.all()]

