"""
Signals for automatic anomaly detection
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from scanning.models import Vulnerability, Scan
from .anomaly_service import AnomalyDetectionService
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Vulnerability)
def detect_vulnerability_anomaly(sender, instance, created, **kwargs):
    """Automatically detect anomalies when vulnerability is created"""
    if created:
        try:
            service = AnomalyDetectionService()
            service.detect_vulnerability_anomalies(instance)
        except Exception as e:
            logger.error(f"Error detecting vulnerability anomaly: {str(e)}")


@receiver(post_save, sender=Scan)
def detect_scan_anomaly(sender, instance, **kwargs):
    """Automatically detect anomalies when scan is completed"""
    # Only run if status is completed and scan was just completed (not on every save)
    # Skip if update_fields was used to prevent running on partial updates
    if instance.status == 'completed':
        update_fields = kwargs.get('update_fields')
        # Skip if this is a partial update that doesn't include status change
        if update_fields and 'status' not in update_fields:
            return
        try:
            service = AnomalyDetectionService()
            service.detect_scan_anomalies(instance)
        except Exception as e:
            logger.error(f"Error detecting scan anomaly: {str(e)}")
            # Don't let signal errors affect scan status - just log and continue

