"""
Admin configuration for alerts module
"""
from django.contrib import admin
from .models import Alert, AlertRule


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'alert_type', 'channel', 'status', 'severity', 'sent_at', 'created_at']
    list_filter = ['alert_type', 'channel', 'status', 'severity', 'created_at']
    search_fields = ['title', 'message', 'vulnerability__title']
    readonly_fields = ['sent_at', 'acknowledged_at', 'created_at', 'updated_at']


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_active', 'severity_threshold', 'send_email', 
                   'create_jira_ticket', 'create_servicenow_ticket', 'created_by', 'created_at']
    list_filter = ['is_active', 'severity_threshold', 'send_email', 'created_at']
    search_fields = ['name', 'description']
    filter_horizontal = ['notify_users']

