"""
Management command to create default users with different roles
"""
from django.core.management.base import BaseCommand
from authentication.models import User


class Command(BaseCommand):
    help = 'Create default users with different roles'

    def handle(self, *args, **options):
        # Create Security Analyst
        analyst, created = User.objects.get_or_create(
            username='analyst',
            defaults={
                'email': 'analyst@savior.com',
                'first_name': 'Security',
                'last_name': 'Analyst',
                'role': 'security_analyst',
                'is_staff': False,
            }
        )
        if created:
            analyst.set_password('analyst123')
            analyst.save()
            self.stdout.write(self.style.SUCCESS('Created Security Analyst user'))
        else:
            self.stdout.write(self.style.WARNING('Security Analyst user already exists'))

        # Create Compliance Officer
        officer, created = User.objects.get_or_create(
            username='compliance',
            defaults={
                'email': 'compliance@savior.com',
                'first_name': 'Compliance',
                'last_name': 'Officer',
                'role': 'compliance_officer',
                'is_staff': False,
            }
        )
        if created:
            officer.set_password('compliance123')
            officer.save()
            self.stdout.write(self.style.SUCCESS('Created Compliance Officer user'))
        else:
            self.stdout.write(self.style.WARNING('Compliance Officer user already exists'))

        # Create SOC Manager
        manager, created = User.objects.get_or_create(
            username='soc_manager',
            defaults={
                'email': 'soc@savior.com',
                'first_name': 'SOC',
                'last_name': 'Manager',
                'role': 'soc_manager',
                'is_staff': True,
            }
        )
        if created:
            manager.set_password('soc123')
            manager.save()
            self.stdout.write(self.style.SUCCESS('Created SOC Manager user'))
        else:
            self.stdout.write(self.style.WARNING('SOC Manager user already exists'))

        self.stdout.write(self.style.SUCCESS('\nDefault users created successfully!'))
        self.stdout.write(self.style.SUCCESS('Security Analyst: analyst / analyst123'))
        self.stdout.write(self.style.SUCCESS('Compliance Officer: compliance / compliance123'))
        self.stdout.write(self.style.SUCCESS('SOC Manager: soc_manager / soc123'))

