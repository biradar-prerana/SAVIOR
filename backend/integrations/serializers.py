"""
Serializers for integrations module
"""
from rest_framework import serializers
from .models import Integration, IntegrationEvent, WebhookEndpoint


class IntegrationSerializer(serializers.ModelSerializer):
    """Serializer for Integration"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = Integration
        fields = ['id', 'name', 'integration_type', 'status', 'config', 'credentials', 'is_enabled',
                  'created_by', 'created_by_username', 'created_at', 'updated_at',
                  'last_sync', 'error_message']
        read_only_fields = ['created_by', 'created_at', 'updated_at', 'last_sync']
        extra_kwargs = {
            'credentials': {'write_only': True},  # Don't expose credentials in responses
        }


class IntegrationEventSerializer(serializers.ModelSerializer):
    """Serializer for IntegrationEvent"""
    integration_name = serializers.CharField(source='integration.name', read_only=True)
    
    class Meta:
        model = IntegrationEvent
        fields = ['id', 'integration', 'integration_name', 'event_type', 'payload',
                  'status', 'sent_at', 'error_message', 'created_at']
        read_only_fields = ['sent_at', 'created_at']


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """Serializer for WebhookEndpoint"""
    integration_name = serializers.CharField(source='integration.name', read_only=True)
    
    class Meta:
        model = WebhookEndpoint
        fields = ['id', 'integration', 'integration_name', 'url', 'method', 'headers',
                  'is_active', 'created_at']
        read_only_fields = ['created_at']
        extra_kwargs = {
            'secret': {'write_only': True},  # Don't expose secret in responses
        }

