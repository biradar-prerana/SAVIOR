"""
Admin configuration for integrations module
"""
from django.contrib import admin
from .models import Integration, IntegrationEvent, WebhookEndpoint


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = ['name', 'integration_type', 'status', 'is_enabled', 'created_by', 'created_at', 'last_sync']
    list_filter = ['integration_type', 'status', 'is_enabled', 'created_at']
    search_fields = ['name']


@admin.register(IntegrationEvent)
class IntegrationEventAdmin(admin.ModelAdmin):
    list_display = ['integration', 'event_type', 'status', 'sent_at', 'created_at']
    list_filter = ['event_type', 'status', 'created_at']
    search_fields = ['integration__name']


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ['integration', 'url', 'method', 'is_active', 'created_at']
    list_filter = ['method', 'is_active', 'created_at']
    search_fields = ['url', 'integration__name']

