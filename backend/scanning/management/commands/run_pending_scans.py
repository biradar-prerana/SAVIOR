from django.core.management.base import BaseCommand
from django.utils import timezone
from scanning.models import Scan
from scanning.scan_engines import get_scanner_for_scan


class Command(BaseCommand):
    help = 'Run all pending scans automatically'

    def handle(self, *args, **options):
        qs = Scan.objects.filter(status__in=['pending', 'failed'])
        count = qs.count()
        self.stdout.write(f'Found {count} scans to run')
        for scan in qs:
            try:
                scan.status = 'running'
                scan.started_at = timezone.now()
                scan.error_message = ''
                scan.save(update_fields=['status', 'started_at', 'error_message'])
                scanner = get_scanner_for_scan(scan)
                scanner.scan_target()
                self.stdout.write(self.style.SUCCESS(f'✓ Scan {scan.id} completed'))
            except Exception as e:
                scan.status = 'failed'
                scan.error_message = str(e)
                scan.completed_at = timezone.now()
                scan.save(update_fields=['status', 'error_message', 'completed_at'])
                self.stdout.write(self.style.ERROR(f'✗ Scan {scan.id} failed: {str(e)}'))
