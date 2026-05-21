"""
Views for reporting module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.http import FileResponse, HttpResponse
from django.conf import settings
import os
from .models import Report, ReportTemplate, ReportSchedule
from .serializers import ReportSerializer, ReportTemplateSerializer, ReportScheduleSerializer
from .report_generator import VulnerabilityReportGenerator
from scanning.models import Scan, ScanTarget, Vulnerability
from savior_backend.mongodb import mongodb_connection


class ReportViewSet(viewsets.ModelViewSet):
    """ViewSet for managing reports"""
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all reports for monitoring purposes
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return Report.objects.all().select_related('scan', 'target', 'generated_by').order_by('-generated_at')
        else:
            return Report.objects.filter(generated_by=self.request.user).select_related('scan', 'target', 'generated_by').order_by('-generated_at')
    
    def perform_create(self, serializer):
        serializer.save(generated_by=self.request.user)
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download report file"""
        report = self.get_object()
        if not report.file_path or not os.path.exists(report.file_path):
            return Response(
                {'error': 'Report file not available'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            file_handle = open(report.file_path, 'rb')
            response = FileResponse(
                file_handle,
                content_type='application/pdf' if report.format == 'pdf' else 'text/html'
            )
            filename = os.path.basename(report.file_path)
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        except Exception as e:
            return Response(
                {'error': f'Error downloading file: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate a new report"""
        scan_id = request.data.get('scan_id')
        target_id = request.data.get('target_id')
        vulnerability_id = request.data.get('vulnerability_id')  # Support for single vulnerability report
        all_vulnerabilities = request.data.get('all_vulnerabilities', False)
        report_type = request.data.get('report_type', 'scan')
        format = request.data.get('format', 'pdf')
        report_name = request.data.get('report_name', None)
        
        # Determine vulnerabilities to include in report
        if vulnerability_id:
            # Single vulnerability report
            vulnerabilities = Vulnerability.objects.filter(id=vulnerability_id).select_related('cve_data', 'risk_score', 'scan', 'scan__target')
            if not vulnerabilities.exists():
                return Response(
                    {'error': 'Vulnerability not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            scan = vulnerabilities.first().scan
            target = scan.target if scan else None
        elif all_vulnerabilities:
            # Compliance officers can generate reports from all vulnerabilities
            if request.user.is_compliance_officer() or request.user.is_soc_manager():
                vulnerabilities = Vulnerability.objects.all().select_related('cve_data', 'risk_score', 'scan', 'scan__target')
            else:
                # Filter by user's scans
                user_scans = Scan.objects.filter(initiated_by=request.user)
                vulnerabilities = Vulnerability.objects.filter(scan__in=user_scans).select_related('cve_data', 'risk_score', 'scan', 'scan__target')
            scan = None
            target = None
            if not vulnerabilities.exists():
                return Response(
                    {'error': 'No vulnerabilities found for report generation'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        elif not scan_id and not target_id:
            return Response(
                {'error': 'Either scan_id, target_id, vulnerability_id, or all_vulnerabilities is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            # Original scan or target based filtering
            scan = None
            target = None
            
            if scan_id:
                scan = Scan.objects.select_related('target').get(id=scan_id)
                target = scan.target
                vulnerabilities = Vulnerability.objects.filter(scan=scan).select_related('cve_data', 'risk_score')
            elif target_id:
                target = ScanTarget.objects.get(id=target_id)
                # Get latest scan for target
                scan = Scan.objects.filter(target=target, status='completed').order_by('-completed_at').first()
                if scan:
                    vulnerabilities = Vulnerability.objects.filter(scan=scan).select_related('cve_data', 'risk_score')
                else:
                    vulnerabilities = Vulnerability.objects.none()
            
            if not vulnerabilities.exists():
                return Response(
                    {'error': 'No vulnerabilities found for report generation'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        try:
            # Generate report
            generator = VulnerabilityReportGenerator(scan=scan, target=target)
            
            if format == 'pdf':
                file_path, file_content = generator.generate_pdf_report(vulnerabilities, report_name)
            elif format == 'html':
                file_path, file_content = generator.generate_html_report(vulnerabilities, report_name)
            else:
                return Response(
                    {'error': f'Unsupported format: {format}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create report record
            if report_name is None:
                report_name = f"Report_{timezone.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Prepare report data
            report_data = {
                'total_vulnerabilities': vulnerabilities.count(),
                'critical_count': vulnerabilities.filter(severity='critical').count(),
                'high_count': vulnerabilities.filter(severity='high').count(),
                'medium_count': vulnerabilities.filter(severity='medium').count(),
                'low_count': vulnerabilities.filter(severity='low').count(),
            }
            
            report = Report.objects.create(
                name=report_name,
                report_type=report_type,
                format=format,
                scan=scan,
                target=target,
                generated_by=request.user,
                file_path=file_path,
                report_data=report_data
            )
            
            try:
                collection = mongodb_connection.get_collection('reporting_report')
                collection.insert_one({
                    'report_id': report.id,
                    'name': report.name,
                    'report_type': report.report_type,
                    'format': report.format,
                    'scan_id': getattr(report.scan, 'id', None),
                    'target_id': getattr(report.target, 'id', None),
                    'generated_by': request.user.username,
                    'generated_at': report.generated_at.isoformat(),
                    'file_path': report.file_path,
                    'report_data': report.report_data,
                })
            except Exception:
                pass
            
            serializer = self.get_serializer(report)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Scan.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except ScanTarget.DoesNotExist:
            return Response(
                {'error': 'Target not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error generating report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ReportTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for managing report templates"""
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all report templates
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return ReportTemplate.objects.all().order_by('-created_at')
        else:
            return ReportTemplate.objects.filter(created_by=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class ReportScheduleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing report schedules"""
    queryset = ReportSchedule.objects.all()
    serializer_class = ReportScheduleSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all report schedules
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            return ReportSchedule.objects.all().order_by('-created_at')
        else:
            return ReportSchedule.objects.filter(created_by=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle schedule active status"""
        schedule = self.get_object()
        schedule.is_active = not schedule.is_active
        schedule.save()
        return Response({'is_active': schedule.is_active})

