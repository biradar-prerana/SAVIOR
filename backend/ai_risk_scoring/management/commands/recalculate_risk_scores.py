"""
Management command to recalculate AI risk scores for all vulnerabilities
"""
from django.core.management.base import BaseCommand
from scanning.models import Vulnerability
from ai_risk_scoring.ml_service import MLRiskScoringService


class Command(BaseCommand):
    help = 'Recalculate AI risk scores for all vulnerabilities'

    def handle(self, *args, **options):
        ml_service = MLRiskScoringService()
        vulns = Vulnerability.objects.all().select_related('cve_data')
        total = vulns.count()
        self.stdout.write(f'Recalculating risk scores for {total} vulnerabilities...')
        updated = 0
        for v in vulns:
            try:
                rs = ml_service.calculate_risk_score(v)
                updated += 1
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Failed for vulnerability {v.id}: {str(e)}'))
        self.stdout.write(self.style.SUCCESS(f'✓ Updated {updated}/{total} risk scores'))
