"""
Views for alerts module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import Alert, AlertRule
from .serializers import AlertSerializer, AlertRuleSerializer
from .alert_service import AlertService
from scanning.models import Vulnerability
from authentication.permissions import IsSOCManager
import logging

logger = logging.getLogger(__name__)


class AlertViewSet(viewsets.ModelViewSet):
    """ViewSet for managing alerts"""
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = Alert.objects.select_related('vulnerability', 'scan', 'target', 'integration', 'acknowledged_by').all()
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by channel
        channel = self.request.query_params.get('channel', None)
        if channel:
            queryset = queryset.filter(channel=channel)
        
        # Filter by severity
        severity = self.request.query_params.get('severity', None)
        if severity:
            queryset = queryset.filter(severity=severity)
        
        return queryset.order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        """Robust list endpoint that avoids 500 due to serialization edge cases"""
        try:
            queryset = self.filter_queryset(self.get_queryset())
            
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error listing alerts: {str(e)}", exc_info=True)
            # Return empty list with 200 to avoid breaking frontend
            page = self.paginate_queryset([])
            if page is not None:
                return self.get_paginated_response([])
            return Response([], status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert"""
        alert = self.get_object()
        alert.status = 'acknowledged'
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = request.user
        alert.save()
        
        serializer = self.get_serializer(alert)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def send_alert(self, request):
        """Manually send alert for a vulnerability"""
        vulnerability_id = request.data.get('vulnerability_id')
        alert_rule_id = request.data.get('alert_rule_id', None)
        
        if not vulnerability_id:
            return Response(
                {'error': 'vulnerability_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            vulnerability = Vulnerability.objects.select_related('scan', 'risk_score').get(id=vulnerability_id)
            
            alert_rule = None
            if alert_rule_id:
                alert_rule = AlertRule.objects.get(id=alert_rule_id)
            
            alert_service = AlertService()
            alerts = alert_service.send_critical_vulnerability_alert(vulnerability, alert_rule)
            
            serializer = self.get_serializer(alerts, many=True)
            return Response({
                'message': f'{len(alerts)} alert(s) sent',
                'alerts': serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except Vulnerability.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error sending alert: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AlertRuleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing alert rules"""
    queryset = AlertRule.objects.all()
    serializer_class = AlertRuleSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all alert rules for monitoring
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return AlertRule.objects.all().order_by('-created_at')
        else:
            return AlertRule.objects.filter(created_by=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Test alert rule with a sample vulnerability"""
        rule = self.get_object()
        vulnerability_id = request.data.get('vulnerability_id')
        
        if not vulnerability_id:
            return Response(
                {'error': 'vulnerability_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            vulnerability = Vulnerability.objects.get(id=vulnerability_id)
            alert_service = AlertService()
            alerts = alert_service.send_critical_vulnerability_alert(vulnerability, rule)
            
            return Response({
                'message': f'Test alert sent. {len(alerts)} alert(s) created.',
                'alerts': AlertSerializer(alerts, many=True).data
            })
        except Vulnerability.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )

