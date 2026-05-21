from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import ScanTarget, Scan, Vulnerability
from .cve_models import CVEData


User = get_user_model()


class ScanningCVELinkingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='tester',
            password='testpass123',
            email='tester@example.com'
        )
        self.target = ScanTarget.objects.create(
            name='Test Target',
            target_url='https://example.com',
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

    def test_cve_link_on_create(self):
        cve = CVEData.objects.create(
            cve_id='CVE-2024-1234',
            description='Test CVE',
            cvss_v3_score=8.2,
            cvss_v3_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity='high',
        )

        vuln = Vulnerability.objects.create(
            scan=self.scan,
            title='Test Vulnerability',
            description='Desc',
            severity='high',
            cve_id=cve.cve_id,
            location='https://example.com',
        )

        vuln.refresh_from_db()
        self.assertIsNotNone(vuln.cve_data)
        self.assertEqual(vuln.cve_data_id, cve.id)
        self.assertEqual(vuln.cvss_score, 8.2)
        self.assertTrue(vuln.cvss_vector.startswith('CVSS:3'))

    def test_cve_link_on_update(self):
        cve = CVEData.objects.create(
            cve_id='CVE-2023-9999',
            description='Test CVE 2',
            cvss_v3_score=7.5,
            cvss_v3_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity='high',
        )

        vuln = Vulnerability.objects.create(
            scan=self.scan,
            title='Test Vulnerability 2',
            description='Desc',
            severity='medium',
            location='https://example.com/path',
        )

        self.assertIsNone(vuln.cve_data)
        vuln.cve_id = cve.cve_id
        vuln.save()
        vuln.refresh_from_db()
        self.assertIsNotNone(vuln.cve_data)
        self.assertEqual(vuln.cvss_score, 7.5)

    def test_cwe_ids_do_not_link(self):
        vuln = Vulnerability.objects.create(
            scan=self.scan,
            title='CWE Vulnerability',
            description='Desc',
            severity='low',
            cve_id='CWE-200',
            location='https://example.com',
        )
        vuln.refresh_from_db()
        self.assertIsNone(vuln.cve_data)
