"""
Views for scanning module
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q
import threading
from .models import ScanTarget, Scan, Vulnerability
from .serializers import (
    ScanTargetSerializer, ScanSerializer, VulnerabilitySerializer, ScanCreateSerializer
)
import logging

logger = logging.getLogger(__name__)


class ScanTargetViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan targets"""
    queryset = ScanTarget.objects.all()
    serializer_class = ScanTargetSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_soc_manager():
            queryset = ScanTarget.objects.filter(is_active=True)
        else:
            queryset = ScanTarget.objects.filter(created_by=self.request.user, is_active=True)
        logger.info(f"User {self.request.user.username} - Found {queryset.count()} targets")
        return queryset
    
    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        logger.info(f"Targets list response for user {request.user.username}: {len(response.data.get('results', response.data) if isinstance(response.data, dict) else response.data)} items")
        return response
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class ScanViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scans"""
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Compliance officers can see all scans for reporting purposes
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            queryset = Scan.objects.all().select_related('target')
        else:
            queryset = Scan.objects.filter(initiated_by=self.request.user).select_related('target')
        logger.info(f"User {self.request.user.username} - Found {queryset.count()} scans")
        return queryset
    
    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        logger.info(f"Scans list response for user {request.user.username}: {len(response.data.get('results', response.data) if isinstance(response.data, dict) else response.data)} items")
        return response
    
    def perform_create(self, serializer):
        serializer.save(initiated_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a scan"""
        scan = self.get_object()
        
        # Check if scan can be started
        if scan.status not in ['pending', 'failed']:
            return Response(
                {'error': f'Scan cannot be started. Current status: {scan.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not scan.target or not scan.target.target_url:
            return Response(
                {'error': 'Target URL is required for scanning'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update scan status to running
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.error_message = ''  # Clear any previous errors
        scan.save()
        
        logger.info(f"Starting scan {scan.id} for target {scan.target.target_url} by user {request.user.username}")
        
        # Run scanner asynchronously for faster API response
        def _run_scan_background(scan_id):
            try:
                from .scan_engines import get_scanner_for_scan
                local_scan = Scan.objects.get(id=scan_id)
                logger.info(f"[Async] Creating scanner for scan {local_scan.id}, target: {local_scan.target.target_url}")
                scanner = get_scanner_for_scan(local_scan)
                logger.info(f"[Async] Starting scan_target() for scan {local_scan.id}")
                scanner.scan_target()
                logger.info(f"[Async] scan_target() completed for scan {local_scan.id}")
            except Exception as e:
                logger.error(f"[Async] Error starting scan {scan_id}: {str(e)}", exc_info=True)
                try:
                    local_scan = Scan.objects.get(id=scan_id)
                    local_scan.status = 'failed'
                    local_scan.error_message = str(e)
                    local_scan.completed_at = timezone.now()
                    local_scan.save(update_fields=['status', 'error_message', 'completed_at'])
                except Exception:
                    pass
        
        threading.Thread(target=_run_scan_background, args=(scan.id,), daemon=True).start()
        
        return Response({
            'status': 'running',
            'scan_id': scan.id,
            'message': 'Scan started. It may take a few moments to complete.',
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a running scan"""
        scan = self.get_object()
        if scan.status not in ['pending', 'running']:
            return Response(
                {'error': 'Scan cannot be cancelled'},
                status=status.HTTP_400_BAD_REQUEST
            )
        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.save()
        return Response({'status': 'Scan cancelled'})
    
    @action(detail=True, methods=['get'])
    def vulnerabilities(self, request, pk=None):
        """Get vulnerabilities for a scan"""
        scan = self.get_object()
        
        # Check if user has permission to view this scan
        if scan.initiated_by != request.user:
            # Check if user created the target
            if scan.target.created_by != request.user:
                return Response(
                    {'error': 'You do not have permission to view vulnerabilities for this scan'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Use direct filter with select_related to load all necessary relationships
        # This ensures scan.target is loaded for the serializer
        # Note: risk_score is optional - don't use select_related for it to avoid table errors
        # The serializer handles risk_score gracefully with error handling
        vulnerabilities = Vulnerability.objects.filter(scan_id=scan.id).select_related(
            'scan', 'scan__target'
        ).order_by('-detected_at')
        vuln_count = vulnerabilities.count()
        
        # Log for debugging
        logger.info(f"Scan {scan.id} vulnerabilities endpoint - User: {request.user.username}")
        logger.info(f"  - Scan status: {scan.status}")
        logger.info(f"  - Scan initiated by: {scan.initiated_by.username}")
        logger.info(f"  - Request user: {request.user.username}")
        logger.info(f"  - Total vulnerabilities in DB for this scan (direct query): {vuln_count}")
        logger.info(f"  - Scan total_vulnerabilities field: {scan.total_vulnerabilities}")
        
        # Also check via relationship for comparison
        relationship_count = scan.vulnerabilities.count()
        logger.info(f"  - Relationship query count: {relationship_count}")
        
        # If scan is completed but no vulnerabilities, automatically add an informational one
        # This fixes old scans that were completed before the fix
        if scan.status == 'completed' and vuln_count == 0:
            logger.warning(f"  - WARNING: Scan {scan.id} is completed but has no vulnerabilities!")
            logger.warning(f"  - Scan total_vulnerabilities field: {scan.total_vulnerabilities}")
            logger.warning(f"  - This is an old scan. Adding informational vulnerability entry...")
            
            # Try to manually check the database first
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM scanning_vulnerability WHERE scan_id = %s", [scan.id])
                db_count = cursor.fetchone()[0]
                logger.warning(f"  - Direct DB query shows {db_count} vulnerabilities for scan {scan.id}")
            
            # If still 0, create an informational vulnerability for this old scan
            if db_count == 0:
                try:
                    target_url = scan.target.target_url if scan.target else 'Unknown'
                    Vulnerability.objects.create(
                        scan_id=scan.id,
                        title='Security Scan Completed',
                        description=f'Security scan completed for {target_url}. This scan was completed before the vulnerability tracking update. No specific vulnerabilities were recorded in the original scan results.',
                        severity='info',
                        vulnerability_type='Scan Summary',
                        location=target_url,
                        cve_id=None,
                        cvss_score=0.0,
                        recommendation='Run a new scan to get detailed vulnerability information with the updated scanner.',
                        evidence={'url': target_url, 'scan_id': scan.id, 'note': 'Retroactively added for old scan'},
                        remediation_steps=[
                            'Run a new scan to get current vulnerability status',
                            'Review scan results regularly',
                            'Keep security tools updated'
                        ]
                    )
                    logger.info(f"  - ✓ Successfully added informational vulnerability to scan {scan.id}")
                    
                    # Refresh the queryset to include the new vulnerability
                    vulnerabilities = Vulnerability.objects.filter(scan_id=scan.id).select_related(
                        'scan', 'scan__target', 'risk_score'
                    ).order_by('-detected_at')
                    vuln_count = vulnerabilities.count()
                    logger.info(f"  - Now scan {scan.id} has {vuln_count} vulnerabilities")
                    
                    # Update scan summary
                    scan.total_vulnerabilities = vuln_count
                    scan.info_count = 1
                    scan.save(update_fields=['total_vulnerabilities', 'info_count'])
                except Exception as e:
                    logger.error(f"  - ERROR adding vulnerability to old scan {scan.id}: {str(e)}", exc_info=True)
                    # Continue with empty vulnerabilities - at least we tried
        
        # Serialize vulnerabilities with error handling
        try:
            serializer = VulnerabilitySerializer(vulnerabilities, many=True)
            serialized_count = len(serializer.data)
            logger.info(f"  - Serialized {serialized_count} vulnerabilities")
            
            # Log first few vulnerabilities for debugging
            if serializer.data:
                logger.info(f"  - First vulnerability ID: {serializer.data[0].get('id')}, Title: {serializer.data[0].get('title')}")
            else:
                logger.warning(f"  - No vulnerabilities in serialized data despite {vuln_count} in queryset!")
                # If serialization failed but we have vulnerabilities, try to identify the issue
                if vuln_count > 0:
                    first_vuln = vulnerabilities.first()
                    logger.warning(f"  - First vulnerability object: ID={first_vuln.id}, Title={first_vuln.title}")
                    logger.warning(f"  - Scan: {first_vuln.scan_id}, Target: {first_vuln.scan.target.name if first_vuln.scan.target else 'None'}")
        except Exception as e:
            logger.error(f"  - ERROR serializing vulnerabilities: {str(e)}", exc_info=True)
            # Return empty list if serialization fails
            return Response([])
        
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def upload_host_inventory(self, request, pk=None):
        scan = self.get_object()
        data = request.data if isinstance(request.data, dict) else {}
        host_inventory = data.get('host_inventory')
        if not host_inventory or not isinstance(host_inventory, dict):
            return Response({'error': 'host_inventory dict is required'}, status=status.HTTP_400_BAD_REQUEST)
        cfg = scan.scan_config or {}
        cfg['host_inventory'] = host_inventory
        scan.scan_config = cfg
        scan.save(update_fields=['scan_config'])
        return Response({'status': 'host inventory saved'})

    @action(detail=True, methods=['post'])
    def upload_oval(self, request, pk=None):
        import os
        from django.conf import settings
        scan = self.get_object()
        data = request.data if isinstance(request.data, dict) else {}
        oval_xml = data.get('oval_xml')
        if not oval_xml or not isinstance(oval_xml, str):
            return Response({'error': 'oval_xml string is required'}, status=status.HTTP_400_BAD_REQUEST)
        base_dir = getattr(settings, 'MEDIA_ROOT', None) or os.path.join(settings.BASE_DIR, 'backend', 'media')
        oval_dir = os.path.join(base_dir, 'oval')
        os.makedirs(oval_dir, exist_ok=True)
        file_path = os.path.join(oval_dir, f'scan_{scan.id}_{int(timezone.now().timestamp())}.xml')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(oval_xml)
        cfg = scan.scan_config or {}
        cfg['oval_path'] = file_path
        scan.scan_config = cfg
        scan.save(update_fields=['scan_config'])
        return Response({'status': 'oval saved', 'path': file_path})

    @action(detail=True, methods=['post'])
    def evaluate_oval(self, request, pk=None):
        scan = self.get_object()
        cfg = scan.scan_config or {}
        oval_path = cfg.get('oval_path')
        host_inventory = cfg.get('host_inventory')
        if not oval_path:
            return Response({'error': 'oval_path not set. Use upload_oval.'}, status=status.HTTP_400_BAD_REQUEST)
        if not host_inventory:
            return Response({'error': 'host_inventory not set. Use upload_host_inventory.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            from .oval_service import OVALEvaluator
            evaluator = OVALEvaluator(scan)
            defs = evaluator.parse_oval(oval_path)
            matches = evaluator.evaluate(host_inventory, defs)
            created = evaluator.create_vulnerabilities(matches)
            scan.update_summary()
            return Response({'status': 'evaluated', 'definitions': len(defs), 'matches': len(matches), 'vulnerabilities_created': created})
        except Exception as e:
            logger.error(f"OVAL evaluation failed for scan {scan.id}: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VulnerabilityViewSet(viewsets.ModelViewSet):
    """ViewSet for managing vulnerabilities"""
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None  # Disable pagination to return all vulnerabilities
    
    def get_queryset(self):
        # Compliance officers can see all vulnerabilities for reporting purposes
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            queryset = Vulnerability.objects.all().select_related(
                'scan', 'scan__target'
            ).order_by('-detected_at')
        else:
            # Filter by user's scans and targets, and prefetch risk_score
            user_scans = Scan.objects.filter(initiated_by=self.request.user)
            user_targets = ScanTarget.objects.filter(created_by=self.request.user)
            
            # Get vulnerabilities from user's scans OR from scans of user's targets
            # Use Q objects for better query handling
            query = Q(scan__in=user_scans)
            if user_targets.exists():
                scans_from_user_targets = Scan.objects.filter(target__in=user_targets)
                if scans_from_user_targets.exists():
                    query = query | Q(scan__in=scans_from_user_targets)
            
            # If no query conditions, return empty queryset (but still log)
            if not user_scans.exists() and not user_targets.exists():
                logger.warning(f"VulnerabilityViewSet - User {self.request.user.username} has no scans or targets")
                return Vulnerability.objects.none()
            
            # Note: risk_score is optional - don't use select_related for it to avoid table errors
            # The serializer handles risk_score gracefully with error handling
            queryset = Vulnerability.objects.filter(query).select_related(
                'scan', 'scan__target'
            ).order_by('-detected_at')
        
        # Log for debugging
        all_vulns_count = Vulnerability.objects.all().count()
        logger.info(f"VulnerabilityViewSet.get_queryset - User: {self.request.user.username}")
        logger.info(f"  - All vulnerabilities in DB: {all_vulns_count}")
        
        if self.request.user.is_compliance_officer() or self.request.user.is_soc_manager():
            logger.info(f"  - User is compliance officer/SOC manager - showing all vulnerabilities")
        else:
            user_scans_list = list(user_scans.values_list('id', flat=True))
            user_targets_list = list(user_targets.values_list('id', flat=True))
            logger.info(f"  - User scans count: {user_scans.count()}, IDs: {user_scans_list}")
            logger.info(f"  - User targets count: {user_targets.count()}, IDs: {user_targets_list}")
            
            # Get scans from user targets
            scans_from_user_targets = Scan.objects.filter(target__in=user_targets) if user_targets.exists() else Scan.objects.none()
            scans_from_user_targets_list = list(scans_from_user_targets.values_list('id', flat=True))
            logger.info(f"  - Scans from user targets count: {scans_from_user_targets.count()}, IDs: {scans_from_user_targets_list}")
        
        filtered_count = queryset.count()
        logger.info(f"  - Filtered vulnerabilities count: {filtered_count}")
        
        # If no vulnerabilities found, log more details
        if filtered_count == 0:
            if all_vulns_count > 0:
                if not (self.request.user.is_compliance_officer() or self.request.user.is_soc_manager()):
                    logger.warning(f"  - WARNING: {all_vulns_count} vulnerabilities exist but none match user filter!")
                    # Check if any vulnerabilities exist for user's scans
                    for scan_id in user_scans_list:
                        scan_vulns = Vulnerability.objects.filter(scan_id=scan_id).count()
                        logger.info(f"  - Scan {scan_id} has {scan_vulns} vulnerabilities")
                        if scan_vulns > 0:
                            # Check if scan exists and is accessible
                            try:
                                scan = Scan.objects.get(id=scan_id)
                                logger.info(f"    - Scan {scan_id}: status={scan.status}, initiated_by={scan.initiated_by.username}")
                            except Scan.DoesNotExist:
                                logger.error(f"    - Scan {scan_id} does not exist!")
                else:
                    logger.warning(f"  - WARNING: {all_vulns_count} vulnerabilities exist but compliance user got 0!")
            else:
                logger.info(f"  - No vulnerabilities in database at all")
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        """Override list to add more logging and error handling"""
        try:
            queryset = self.get_queryset()
            logger.info(f"VulnerabilityViewSet.list - Queryset count: {queryset.count()}")
            
            # Try to serialize a sample to check for errors
            if queryset.exists():
                sample = queryset.first()
                try:
                    serializer = VulnerabilitySerializer(sample)
                    logger.debug(f"  - Sample vulnerability serialized successfully: {sample.id}")
                except Exception as e:
                    logger.error(f"  - ERROR serializing sample vulnerability {sample.id}: {str(e)}", exc_info=True)
            
            response = super().list(request, *args, **kwargs)
            data = response.data.get('results', response.data) if isinstance(response.data, dict) else response.data
            count = len(data) if isinstance(data, list) else 0
            logger.info(f"VulnerabilityViewSet.list - Returning {count} vulnerabilities to user {request.user.username}")
            
            # If queryset has items but response is empty, log warning
            if queryset.count() > 0 and count == 0:
                logger.error(f"  - CRITICAL: Queryset has {queryset.count()} vulnerabilities but response is empty!")
                logger.error(f"  - Response data type: {type(response.data)}")
                logger.error(f"  - Response data: {str(response.data)[:200]}")
            
            return response
        except Exception as e:
            logger.error(f"VulnerabilityViewSet.list - ERROR: {str(e)}", exc_info=True)
            # Return empty response on error
            return Response({'results': [], 'count': 0})
    
    @action(detail=True, methods=['post'])
    def mark_false_positive(self, request, pk=None):
        """Mark a vulnerability as false positive"""
        vulnerability = self.get_object()
        vulnerability.is_false_positive = True
        vulnerability.save()
        return Response({'status': 'Marked as false positive'})
    
    @action(detail=False, methods=['get'])
    def debug(self, request):
        """Debug endpoint to check vulnerability query"""
        user_scans = Scan.objects.filter(initiated_by=request.user)
        user_targets = ScanTarget.objects.filter(created_by=request.user)
        all_vulnerabilities = Vulnerability.objects.all()
        user_vulnerabilities = self.get_queryset()
        
        # Get detailed scan info
        scan_details = []
        for scan in user_scans[:10]:
            vuln_count = scan.vulnerabilities.count()
            scan_details.append({
                'id': scan.id,
                'status': scan.status,
                'target': scan.target.name,
                'target_url': scan.target.target_url,
                'vulnerabilities_count': vuln_count,
                'total_vulnerabilities_field': scan.total_vulnerabilities,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            })
        
        return Response({
            'user': request.user.username,
            'user_scans_count': user_scans.count(),
            'user_targets_count': user_targets.count(),
            'all_vulnerabilities_count': all_vulnerabilities.count(),
            'user_vulnerabilities_count': user_vulnerabilities.count(),
            'scan_details': scan_details,
            'user_vulnerabilities': [{'id': v.id, 'title': v.title, 'scan_id': v.scan.id, 'severity': v.severity} for v in user_vulnerabilities[:10]],
        })

