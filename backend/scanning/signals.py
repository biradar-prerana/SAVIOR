"""
Signals for scanning models
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Vulnerability, Scan
from .cve_utils import link_vulnerability_to_cve
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Vulnerability)
def link_cve_on_vulnerability_save(sender, instance, created, **kwargs):
    """Automatically link CVE data when vulnerability is saved"""
    try:
        if instance.cve_id and not instance.cve_data:
            link_vulnerability_to_cve(instance)
    except Exception:
        # Avoid breaking save operations due to linking issues
        pass


@receiver(post_save, sender=Scan)
def update_scan_summary(sender, instance, **kwargs):
    """Update scan summary when scan is completed"""
    # Only update if status is completed and summary hasn't been set yet
    # Skip if update_fields was used and includes summary fields (to prevent recursion)
    if instance.status == 'completed':
        update_fields = kwargs.get('update_fields')
        # If update_fields includes summary fields, they were already updated
        if update_fields and any(field in update_fields for field in 
                                ['total_vulnerabilities', 'critical_count', 'high_count', 
                                 'medium_count', 'low_count', 'info_count']):
            # Summary was already updated, skip to prevent recursion
            return
        
        # Only update if summary fields are not already set
        if not instance.scan_summary or instance.total_vulnerabilities is None:
            try:
                instance.update_summary()
            except Exception as e:
                logger.error(f"Error updating scan summary in signal: {str(e)}")
                # Don't let signal errors affect scan status

