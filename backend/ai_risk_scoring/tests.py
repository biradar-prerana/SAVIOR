from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from scanning.models import ScanTarget, Scan, Vulnerability
from scanning.cve_models import CVEData
from .ml_service import MLRiskScoringService


User = get_user_model()


class RiskScoringFallbackTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='risktester',
            password='testpass123',
            email='risk@test.com'
        )
        self.target = ScanTarget.objects.create(
            name='Risk Target',
            target_url='https://risk.example.com',
            target_type='web',
            created_by=self.user,
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed',
            scan_type='web',
            initiated_by=self.user,
            completed_at=timezone.now(),
        )
        self.service = MLRiskScoringService()

    def test_fallback_uses_vulnerability_cvss_consistently(self):
        vuln = Vulnerability.objects.create(
            scan=self.scan,
            title='Vuln with CVSS',
            description='Desc',
            severity='medium',
            cvss_score=6.5,
            location='https://risk.example.com',
        )

        risk = self.service.calculate_risk_score(vuln)
        self.assertIsNotNone(risk)
        # 6.5 (0-10) should map to 65 (0-100)
        self.assertAlmostEqual(risk.overall_score, 65.0, places=1)
        self.assertAlmostEqual(risk.confidence, 0.5, places=2)

    def test_fallback_uses_cve_data_and_exploit_adjustment(self):
        cve = CVEData.objects.create(
            cve_id='CVE-2022-1111',
            description='Exploit available CVE',
            cvss_v3_score=8.0,
            cvss_v3_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity='high',
            exploit_available=True,
        )
        vuln = Vulnerability.objects.create(
            scan=self.scan,
            title='Linked CVE Vulnerability',
            description='Desc',
            severity='high',
            cve_id=cve.cve_id,
            location='https://risk.example.com/path',
        )

        risk = self.service.calculate_risk_score(vuln)
        self.assertIsNotNone(risk)
        # Base 8.0 → 80, exploit available → 96 (capped at 100)
        self.assertAlmostEqual(risk.overall_score, 96.0, places=1)
        self.assertAlmostEqual(risk.confidence, 0.5, places=2)
