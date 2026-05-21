"""
Signals for automatic alert generation
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from scanning.models import Vulnerability, Scan
from anomaly_detection.models import AnomalyDetection
from .alert_service import AlertService
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Vulnerability)
def send_critical_vulnerability_alert(sender, instance, created, **kwargs):
    """Automatically send alerts for critical vulnerabilities"""
    if created and instance.severity in ['critical', 'high']:
        try:
            alert_service = AlertService()
            alert_service.send_critical_vulnerability_alert(instance)
        except Exception as e:
            logger.error(f"Error sending critical vulnerability alert: {str(e)}")

@receiver(post_save, sender=Scan)
def send_scan_completed_alert(sender, instance, **kwargs):
    """Automatically send summary alerts when a scan is completed with serious findings"""
    if instance.status == 'completed':
        update_fields = kwargs.get('update_fields')
        if update_fields and 'status' not in update_fields:
            return
        try:
            alert_service = AlertService()
            alert_service.send_scan_completed_alert(instance)
        except Exception as e:
            logger.error(f"Error sending scan completed alert: {str(e)}")

@receiver(post_save, sender=AnomalyDetection)
def send_anomaly_detected_alert(sender, instance, created, **kwargs):
    """Automatically send alerts for high/critical anomalies"""
    if created and instance.severity in ['critical', 'high']:
        try:
            alert_service = AlertService()
            alert_service.send_anomaly_alert(instance)
        except Exception as e:
            logger.error(f"Error sending anomaly alert: {str(e)}")
