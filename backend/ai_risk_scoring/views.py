"""
Views for AI Risk Scoring module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import RiskScore, RiskAssessment, AIModel
from .serializers import RiskScoreSerializer, RiskAssessmentSerializer, AIModelSerializer
from .ml_service import MLRiskScoringService
from scanning.models import Scan, Vulnerability
from authentication.permissions import IsSOCManager


class RiskScoreViewSet(viewsets.ModelViewSet):
    """ViewSet for managing risk scores"""
    queryset = RiskScore.objects.all()
    serializer_class = RiskScoreSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all risk scores for reporting purposes
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return RiskScore.objects.all().select_related('vulnerability', 'vulnerability__scan')
        else:
            # Filter by user's vulnerabilities
            user_scans = Scan.objects.filter(initiated_by=self.request.user)
            user_vulnerabilities = Vulnerability.objects.filter(scan__in=user_scans)
            return RiskScore.objects.filter(vulnerability__in=user_vulnerabilities).select_related('vulnerability', 'vulnerability__scan')
    
    @action(detail=False, methods=['post'])
    def calculate(self, request):
        """Calculate risk score for a vulnerability using ML model"""
        vulnerability_id = request.data.get('vulnerability_id')
        if not vulnerability_id:
            return Response(
                {'error': 'vulnerability_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            vulnerability = Vulnerability.objects.select_related('cve_data').get(id=vulnerability_id)
            
            # Use ML service to calculate risk score
            ml_service = MLRiskScoringService()
            risk_score = ml_service.calculate_risk_score(vulnerability)
            
            serializer = self.get_serializer(risk_score)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Vulnerability.DoesNotExist:
            return Response(
                {'error': 'Vulnerability not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error calculating risk score: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RiskAssessmentViewSet(viewsets.ModelViewSet):
    """ViewSet for managing risk assessments"""
    queryset = RiskAssessment.objects.all()
    serializer_class = RiskAssessmentSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all risk assessments for reporting purposes
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return RiskAssessment.objects.all().select_related(
                'scan', 'scan__target', 'generated_by'
            ).order_by('-generated_at')
        else:
            # Filter by user's scans/targets
            user_scans = Scan.objects.filter(initiated_by=self.request.user)
            return RiskAssessment.objects.filter(scan__in=user_scans).select_related(
                'scan', 'scan__target', 'generated_by'
            ).order_by('-generated_at')
    
    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate risk assessment for a scan"""
        import logging
        logger = logging.getLogger(__name__)
        
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get scan and verify user has permission
            # Use select_related to load target relationship
            scan = Scan.objects.select_related('target', 'initiated_by').get(id=scan_id)
            
            # Check if user has permission to access this scan
            if scan.initiated_by != request.user:
                if scan.target.created_by != request.user:
                    return Response(
                        {'error': 'You do not have permission to generate assessment for this scan'},
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            # Check if scan is completed
            if scan.status != 'completed':
                return Response(
                    {'error': f'Scan must be completed before generating assessment. Current status: {scan.status}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get vulnerabilities for this scan using direct query to avoid relationship issues
            vulnerabilities = Vulnerability.objects.filter(scan_id=scan.id)
            vuln_count = vulnerabilities.count()
            
            logger.info(f"Generating risk assessment for scan {scan_id} with {vuln_count} vulnerabilities")
            
            if vuln_count == 0:
                return Response(
                    {'error': 'Cannot generate assessment: scan has no vulnerabilities'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Calculate risk statistics
            critical_count = vulnerabilities.filter(severity='critical').count()
            high_count = vulnerabilities.filter(severity='high').count()
            medium_count = vulnerabilities.filter(severity='medium').count()
            low_count = vulnerabilities.filter(severity='low').count()
            info_count = vulnerabilities.filter(severity='info').count()
            
            # Calculate overall risk score based on vulnerabilities
            # Weight: critical=100, high=75, medium=50, low=25, info=10
            total_weighted_score = (
                critical_count * 100 +
                high_count * 75 +
                medium_count * 50 +
                low_count * 25 +
                info_count * 10
            )
            
            # Normalize to 0-100 scale (divide by total count, but cap at 100)
            if vuln_count > 0:
                risk_score = min(total_weighted_score / vuln_count, 100.0)
            else:
                risk_score = 0.0
            
            # Determine overall risk level
            if risk_score >= 80 or critical_count > 0:
                overall_risk = 'critical'
            elif risk_score >= 60 or high_count > 0:
                overall_risk = 'high'
            elif risk_score >= 40 or medium_count > 0:
                overall_risk = 'medium'
            elif risk_score >= 20 or low_count > 0:
                overall_risk = 'low'
            else:
                overall_risk = 'minimal'
            
            # Generate recommendations based on vulnerabilities
            recommendations = []
            if critical_count > 0:
                recommendations.append(f'Immediately address {critical_count} critical vulnerability(ies)')
            if high_count > 0:
                recommendations.append(f'Prioritize fixing {high_count} high-severity vulnerability(ies)')
            if medium_count > 0:
                recommendations.append(f'Plan remediation for {medium_count} medium-severity vulnerability(ies)')
            if not recommendations:
                recommendations.append('Continue regular security scanning and monitoring')
            
            # Generate AI insights
            ai_insights = {
                'total_vulnerabilities': vuln_count,
                'severity_distribution': {
                    'critical': critical_count,
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count,
                    'info': info_count
                },
                'risk_factors': [],
                'assessment_date': timezone.now().isoformat()
            }
            
            if critical_count > 0:
                ai_insights['risk_factors'].append('Critical vulnerabilities detected - immediate action required')
            if high_count > 0:
                ai_insights['risk_factors'].append('Multiple high-severity issues present')
            if vuln_count > 10:
                ai_insights['risk_factors'].append('High vulnerability count indicates need for comprehensive security review')
            
            # Create assessment
            assessment = RiskAssessment.objects.create(
                scan=scan,
                overall_risk=overall_risk,
                risk_score=risk_score,
                vulnerability_count=vuln_count,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                generated_by=request.user,
                ai_insights=ai_insights,
                recommendations=recommendations
            )
            
            logger.info(f"Successfully generated risk assessment {assessment.id} for scan {scan_id}")
            
            serializer = self.get_serializer(assessment)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Scan.DoesNotExist:
            logger.error(f"Scan {scan_id} not found for user {request.user.username}")
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error generating risk assessment for scan {scan_id}: {str(e)}", exc_info=True)
            return Response(
                {'error': f'Failed to generate assessment: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AIModelViewSet(viewsets.ModelViewSet):
    """ViewSet for managing AI models"""
    queryset = AIModel.objects.all()
    serializer_class = AIModelSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        model_type = self.request.query_params.get('model_type', None)
        queryset = AIModel.objects.all()
        if model_type:
            queryset = queryset.filter(model_type=model_type)
        return queryset.order_by('-created_at')
    
    @action(detail=False, methods=['post'], permission_classes=[IsSOCManager])
    def train(self, request):
        """Train a new risk scoring model"""
        from .ml_service import MLRiskScoringService
        
        model_name = request.data.get('model_name', 'Risk Scoring Model')
        model_version = request.data.get('model_version', '1.0')
        
        try:
            ml_service = MLRiskScoringService()
            ai_model = ml_service.train_model(
                vulnerabilities=None,  # Use all vulnerabilities with CVE data
                model_name=model_name,
                model_version=model_version
            )
            
            serializer = self.get_serializer(ai_model)
            return Response({
                'message': 'Model trained successfully',
                'model': serializer.data,
                'metrics': ai_model.performance_metrics
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
        AIModel.objects.filter(
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

