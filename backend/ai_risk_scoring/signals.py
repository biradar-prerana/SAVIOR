"""
Signals for automatic risk score calculation
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from scanning.models import Vulnerability
from .ml_service import MLRiskScoringService
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Vulnerability)
def calculate_risk_score_on_vulnerability_save(sender, instance, created, **kwargs):
    """Automatically calculate risk score when vulnerability is created"""
    if created:
        try:
            ml_service = MLRiskScoringService()
            risk_score = ml_service.calculate_risk_score(instance)
            logger.info(f"Risk score calculated for vulnerability {instance.id}: {risk_score.overall_score}")
        except Exception as e:
            logger.error(f"Error calculating risk score for vulnerability {instance.id}: {str(e)}")

