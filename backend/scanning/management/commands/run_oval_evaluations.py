from django.core.management.base import BaseCommand
from django.utils import timezone
from scanning.models import Scan
from scanning.oval_service import OVALEvaluator
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Run OVAL evaluations for scans with OVAL definitions and host inventory'

    def handle(self, *args, **options):
        scans = Scan.objects.all()
        count = 0
        for scan in scans:
            cfg = scan.scan_config or {}
            oval_path = cfg.get('oval_path')
            host_inventory = cfg.get('host_inventory')
            if not oval_path or not host_inventory:
                continue
            try:
                evaluator = OVALEvaluator(scan)
                defs = evaluator.parse_oval(oval_path)
                matches = evaluator.evaluate(host_inventory, defs)
                created = evaluator.create_vulnerabilities(matches)
                scan.update_summary()
                count += 1
                logger.info(f"Scan {scan.id}: defs={len(defs)} matches={len(matches)} created={created}")
            except Exception as e:
                logger.error(f"OVAL evaluation failed for scan {scan.id}: {str(e)}")
        logger.info(f"Completed OVAL evaluations for {count} scans at {timezone.now().isoformat()}")
