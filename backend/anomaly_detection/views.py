"""
Views for anomaly detection module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import AnomalyDetection, AnomalyModel, AnomalyBaseline
from .serializers import (
    AnomalyDetectionSerializer, AnomalyModelSerializer, AnomalyBaselineSerializer
)
from .anomaly_service import AnomalyDetectionService
from scanning.models import Vulnerability, Scan, ScanTarget
from authentication.permissions import IsSOCManager


class AnomalyDetectionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing anomaly detections"""
    queryset = AnomalyDetection.objects.all()
    serializer_class = AnomalyDetectionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = AnomalyDetection.objects.all()
        
        # Filter by anomaly type
        anomaly_type = self.request.query_params.get('anomaly_type', None)
        if anomaly_type:
            queryset = queryset.filter(anomaly_type=anomaly_type)
        
        # Filter by severity
        severity = self.request.query_params.get('severity', None)
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter zero-days
        zero_day = self.request.query_params.get('zero_day', None)
        if zero_day == 'true':
            queryset = queryset.filter(is_potential_zero_day=True)
        
        return queryset.order_by('-anomaly_score', '-detected_at')
    
    @action(detail=True, methods=['post'])
    def investigate(self, request, pk=None):
        """Mark anomaly as being investigated"""
        anomaly = self.get_object()
        anomaly.status = 'investigating'
        anomaly.investigated_by = request.user
        anomaly.investigation_notes = request.data.get('notes', '')
        anomaly.save()
        
        serializer = self.get_serializer(anomaly)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def confirm(self, request, pk=None):
        """Confirm anomaly as valid"""
        anomaly = self.get_object()
        anomaly.status = 'confirmed'
        anomaly.investigated_by = request.user
        anomaly.investigation_notes = request.data.get('notes', '')
        anomaly.save()
        
        serializer = self.get_serializer(anomaly)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def mark_false_positive(self, request, pk=None):
        """Mark anomaly as false positive"""
        anomaly = self.get_object()
        anomaly.status = 'false_positive'
        anomaly.investigated_by = request.user
        anomaly.investigation_notes = request.data.get('notes', '')
        anomaly.save()
        
        serializer = self.get_serializer(anomaly)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve anomaly"""
        anomaly = self.get_object()
        anomaly.status = 'resolved'
        anomaly.resolved_at = timezone.now()
        anomaly.investigated_by = request.user
        anomaly.investigation_notes = request.data.get('notes', '')
        anomaly.save()
        
        serializer = self.get_serializer(anomaly)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def detect_vulnerability(self, request):
        """Detect anomalies in a vulnerability"""
        vulnerability_id = request.data.get('vulnerability_id')
        if not vulnerability_id:
            return Response(
                {'error': 'vulnerability_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            vulnerability = Vulnerability.objects.select_related('cve_data', 'scan').get(id=vulnerability_id)
            
            service = AnomalyDetectionService()
            anomaly = service.detect_vulnerability_anomalies(vulnerability)
            
            if anomaly:
                serializer = self.get_serializer(anomaly)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'No anomaly detected'}, status=status.HTTP_200_OK)
                
        except Vulnerability.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error detecting anomaly: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def detect_scan(self, request):
        """Detect anomalies in a scan"""
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            scan = Scan.objects.select_related('target').get(id=scan_id)
            
            service = AnomalyDetectionService()
            anomaly = service.detect_scan_anomalies(scan)
            
            if anomaly:
                serializer = self.get_serializer(anomaly)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'No anomaly detected'}, status=status.HTTP_200_OK)
                
        except Scan.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error detecting anomaly: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def zero_days(self, request):
        """Get all potential zero-day vulnerabilities"""
        zero_days = self.get_queryset().filter(is_potential_zero_day=True)
        serializer = self.get_serializer(zero_days, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def detect_network(self, request):
        """Detect anomalies in network behavior for a target"""
        target_id = request.data.get('target_id')
        network_trace = request.data.get('network_trace', {})
        if not target_id:
            return Response(
                {'error': 'target_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            target = ScanTarget.objects.get(id=target_id)
            service = AnomalyDetectionService()
            anomaly = service.detect_network_anomalies(target, network_trace)
            if anomaly:
                serializer = self.get_serializer(anomaly)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'No network anomaly detected'}, status=status.HTTP_200_OK)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Target not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error detecting network anomaly: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'])
    def detect_logs(self, request):
        """Detect anomalies in system logs for a target"""
        target_id = request.data.get('target_id')
        logs_summary = request.data.get('logs_summary', {})
        if not target_id:
            return Response(
                {'error': 'target_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            target = ScanTarget.objects.get(id=target_id)
            service = AnomalyDetectionService()
            anomaly = service.detect_log_anomalies(target, logs_summary)
            if anomaly:
                serializer = self.get_serializer(anomaly)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'No log anomaly detected'}, status=status.HTTP_200_OK)
        except ScanTarget.DoesNotExist:
            return Response({'error': 'Target not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error detecting log anomaly: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AnomalyModelViewSet(viewsets.ModelViewSet):
    """ViewSet for managing anomaly detection models"""
    queryset = AnomalyModel.objects.all()
    serializer_class = AnomalyModelSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        model_type = self.request.query_params.get('model_type', None)
        queryset = AnomalyModel.objects.all()
        if model_type:
            queryset = queryset.filter(model_type=model_type)
        return queryset.order_by('-created_at')
    
    @action(detail=False, methods=['post'], permission_classes=[IsSOCManager])
    def train(self, request):
        """Train a new anomaly detection model"""
        from .anomaly_service import AnomalyDetectionService
        
        model_name = request.data.get('model_name', 'Anomaly Detection Model')
        model_version = request.data.get('model_version', '1.0')
        model_type = request.data.get('model_type', 'vulnerability')
        contamination = float(request.data.get('contamination', 0.1))
        
        try:
            service = AnomalyDetectionService()
            anomaly_model = service.train_model(
                vulnerabilities=None,
                model_name=model_name,
                model_version=model_version,
                model_type=model_type,
                contamination=contamination
            )
            
            serializer = self.get_serializer(anomaly_model)
            return Response({
                'message': 'Model trained successfully',
                'model': serializer.data,
                'metrics': anomaly_model.performance_metrics
            }, status=status.HTTP_201_CREATED)
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Error training model: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'], permission_classes=[IsSOCManager])
    def activate(self, request, pk=None):
        """Activate a model"""
        model = self.get_object()
        
        # Deactivate other models of same type
        AnomalyModel.objects.filter(
            model_type=model.model_type,
            is_active=True
        ).update(is_active=False)
        
        # Activate this model
        model.is_active = True
        model.save()
        
        serializer = self.get_serializer(model)
        return Response({
            'message': 'Model activated',
            'model': serializer.data
        })


class AnomalyBaselineViewSet(viewsets.ModelViewSet):
    """ViewSet for managing anomaly baselines"""
    queryset = AnomalyBaseline.objects.all()
    serializer_class = AnomalyBaselineSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return AnomalyBaseline.objects.filter(is_active=True)
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=False, methods=['post'])
    def detect_drift(self, request):
        """Detect configuration drift for a target"""
        target_id = request.data.get('target_id')
        current_config = request.data.get('current_config', {})
        baseline_name = request.data.get('baseline_name', None)
        
        if not target_id:
            return Response(
                {'error': 'target_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            target = ScanTarget.objects.get(id=target_id)
            
            service = AnomalyDetectionService()
            anomaly = service.detect_configuration_drift(target, current_config, baseline_name)
            
            if anomaly:
                serializer = AnomalyDetectionSerializer(anomaly)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'No configuration drift detected'}, status=status.HTTP_200_OK)
                
        except ScanTarget.DoesNotExist:
            return Response(
                {'error': 'Target not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error detecting drift: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

