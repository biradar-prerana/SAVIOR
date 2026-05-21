"""
Management command to bootstrap CVE data and sample vulnerabilities
for training the risk scoring model.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from scanning.models import ScanTarget, Scan, Vulnerability
from scanning.cve_utils import update_cve_from_api


class Command(BaseCommand):
    help = 'Bootstrap CVEData and sample Vulnerabilities to enable risk model training'

    SAMPLE_CVES = [
        # CVE ID, baseScore, vectorString, description
        ('CVE-2021-44228', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'Apache Log4j RCE (Log4Shell)'),
        ('CVE-2020-1472', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Netlogon Elevation of Privilege (Zerologon)'),
        ('CVE-2019-0708', 9.8, 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'BlueKeep Remote Desktop Services RCE'),
        ('CVE-2017-0144', 8.1, 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'EternalBlue SMB Exploit'),
        ('CVE-2018-7600', 7.5, 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Drupalgeddon 2'),
        ('CVE-2021-34527', 8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Windows Print Spooler (PrintNightmare)'),
        ('CVE-2017-5638', 7.5, 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Apache Struts Jakarta Multipart Parser RCE'),
        ('CVE-2019-19781', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Citrix ADC Path Traversal'),
        ('CVE-2022-22965', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Spring4Shell'),
        ('CVE-2020-5902', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'F5 BIG-IP TMUI RCE'),
    ]

    def handle(self, *args, **options):
        User = get_user_model()
        user, _ = User.objects.get_or_create(
            username='trainer',
            defaults={
                'email': 'trainer@example.com',
                'password': 'trainer123',
                'role': 'soc_manager'
            }
        )

        target, _ = ScanTarget.objects.get_or_create(
            name='Training Target',
            defaults={
                'target_url': 'https://example.com',
                'target_type': 'web',
                'description': 'Target for bootstrapping risk training data',
                'created_by': user
            }
        )

        scan, _ = Scan.objects.get_or_create(
            target=target,
            initiated_by=user,
            defaults={
                'status': 'completed',
                'scan_type': 'web',
                'completed_at': timezone.now()
            }
        )

        self.stdout.write('Bootstrapping CVEData and sample Vulnerabilities...')
        created_cves = 0
        created_vulns = 0

        for cve_id, score, vector, desc in self.SAMPLE_CVES:
            api_data = {
                'description': desc,
                'cvssV3': {
                    'baseScore': score,
                    'vectorString': vector
                },
                'published': '2021-12-10T00:00:00Z',
                'modified': '2022-01-15T00:00:00Z',
                'references': ['https://nvd.nist.gov/vuln/detail/{}'.format(cve_id)]
            }
            cve = update_cve_from_api(cve_id, api_data)
            if cve:
                created_cves += 1

            vuln, created = Vulnerability.objects.get_or_create(
                scan=scan,
                title=f"Sample vulnerability for {cve_id}",
                defaults={
                    'description': f"Sample record linked to {cve_id}",
                    'severity': 'high',
                    'cve_id': cve_id,
                    'location': target.target_url,
                    'recommendation': 'Apply vendor patches and mitigations.',
                    'vulnerability_type': 'Sample',
                    'evidence': {'source': 'bootstrap'},
                }
            )
            if created:
                created_vulns += 1

        self.stdout.write(self.style.SUCCESS(
            f'✓ Bootstrapped {created_cves} CVEs and {created_vulns} vulnerabilities.'
        ))
        self.stdout.write('You can now run: python manage.py train_risk_model --model-name \"Risk Scoring Model\" --model-version \"1.0\"')
