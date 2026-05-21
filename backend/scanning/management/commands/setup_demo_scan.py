from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from scanning.models import ScanTarget, Scan, Vulnerability
from scanning.scan_engines import get_scanner_for_scan
from alerts.models import AlertRule

class Command(BaseCommand):
    help = 'Setup demo alert rule, target, and run a scan'

    def handle(self, *args, **options):
        User = get_user_model()
        user = User.objects.order_by('-date_joined').first()
        if not user:
            self.stdout.write(self.style.ERROR('No users found'))
            return
        rule, _ = AlertRule.objects.get_or_create(
            name='Demo High Severity Rule',
            defaults={
                'description': 'Demo',
                'is_active': True,
                'severity_threshold': 'high',
                'send_email': True,
                'create_jira_ticket': False,
                'create_servicenow_ticket': False,
                'email_recipients': ['demo@example.com'],
                'created_by': user
            }
        )
        if not rule.created_by_id:
            rule.created_by = user
            rule.save(update_fields=['created_by'])
        rule.notify_users.add(user)
        target, _ = ScanTarget.objects.get_or_create(
            name='TestPHP VulnWeb',
            defaults={
                'target_url': 'http://testphp.vulnweb.com',
                'target_type': 'web',
                'description': 'Demo',
                'created_by': user,
                'is_active': True
            }
        )
        if not target.created_by_id:
            target.created_by = user
            target.save(update_fields=['created_by'])
        scan = Scan.objects.create(
            target=target,
            status='pending',
            scan_type='web',
            initiated_by=user,
            started_at=timezone.now()
        )
        scan.status = 'running'
        scan.save(update_fields=['status'])
        scanner = get_scanner_for_scan(scan)
        scanner.scan_target()
        Vulnerability.objects.create(
            scan_id=scan.id,
            title='Demo High Severity Issue',
            description='Demo',
            severity='high',
            vulnerability_type='Injection',
            location=target.target_url or target.name,
            cve_id=None,
            cvss_score=8.5,
            recommendation='Review input validation',
            evidence={},
            remediation_steps=['Sanitize inputs']
        )
        self.stdout.write(self.style.SUCCESS(f'Setup complete. Scan {scan.id} completed'))
