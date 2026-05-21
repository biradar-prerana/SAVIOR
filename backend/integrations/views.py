"""
Views for integrations module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import Integration, IntegrationEvent, WebhookEndpoint
from .serializers import IntegrationSerializer, IntegrationEventSerializer, WebhookEndpointSerializer


class IntegrationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing integrations"""
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Integration.objects.filter(created_by=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Test integration connection"""
        integration = self.get_object()
        
        if integration.integration_type == 'jira':
            from alerts.jira_service import JiraService
            config = integration.config
            credentials = integration.credentials
            try:
                jira_service = JiraService(
                    base_url=config.get('base_url', ''),
                    username=credentials.get('username', ''),
                    api_token=credentials.get('api_token', ''),
                    project_key=config.get('project_key', '')
                )
                success = jira_service.test_connection()
                return Response({
                    'status': 'success' if success else 'failed',
                    'integration': integration.name,
                    'message': 'Connection successful' if success else 'Connection failed'
                })
            except Exception as e:
                return Response({
                    'status': 'failed',
                    'integration': integration.name,
                    'message': f'Error: {str(e)}'
                })
        elif integration.integration_type == 'servicenow':
            from alerts.servicenow_service import ServiceNowService
            config = integration.config
            credentials = integration.credentials
            try:
                servicenow_service = ServiceNowService(
                    instance_url=config.get('instance_url', ''),
                    username=credentials.get('username', ''),
                    password=credentials.get('password', ''),
                    table_name=config.get('table_name', 'incident')
                )
                success = servicenow_service.test_connection()
                return Response({
                    'status': 'success' if success else 'failed',
                    'integration': integration.name,
                    'message': 'Connection successful' if success else 'Connection failed'
                })
            except Exception as e:
                return Response({
                    'status': 'failed',
                    'integration': integration.name,
                    'message': f'Error: {str(e)}'
                })
        
        return Response({'status': 'Test not implemented', 'integration': integration.name})
    
    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """Sync integration"""
        integration = self.get_object()
        integration.last_sync = timezone.now()
        integration.save()
        # TODO: Implement sync logic
        return Response({'status': 'Sync initiated', 'last_sync': integration.last_sync})
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle integration enabled status"""
        integration = self.get_object()
        integration.is_enabled = not integration.is_enabled
        integration.save()
        return Response({'is_enabled': integration.is_enabled})


class IntegrationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing integration events"""
    queryset = IntegrationEvent.objects.all()
    serializer_class = IntegrationEventSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user_integrations = Integration.objects.filter(created_by=self.request.user)
        return IntegrationEvent.objects.filter(integration__in=user_integrations)


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    """ViewSet for managing webhook endpoints"""
    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user_integrations = Integration.objects.filter(created_by=self.request.user)
        return WebhookEndpoint.objects.filter(integration__in=user_integrations)
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Test webhook endpoint"""
        webhook = self.get_object()
        # TODO: Implement webhook test logic
        return Response({'status': 'Test not implemented', 'url': webhook.url})

