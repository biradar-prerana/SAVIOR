"""
Management command to send a test alert
"""
from django.core.management.base import BaseCommand
from alerts.alert_service import AlertService
from scanning.models import Vulnerability


class Command(BaseCommand):
    help = 'Send a test alert for a vulnerability'

    def add_arguments(self, parser):
        parser.add_argument(
            '--vulnerability-id',
            type=int,
            required=True,
            help='ID of the vulnerability to send alert for'
        )
        parser.add_argument(
            '--alert-rule-id',
            type=int,
            help='ID of the alert rule to use (optional)'
        )

    def handle(self, *args, **options):
        vulnerability_id = options['vulnerability_id']
        alert_rule_id = options.get('alert_rule_id')
        
        try:
            vulnerability = Vulnerability.objects.select_related('scan', 'risk_score').get(id=vulnerability_id)
            self.stdout.write(f'Sending alert for vulnerability: {vulnerability.title}')
            
            alert_rule = None
            if alert_rule_id:
                from alerts.models import AlertRule
                alert_rule = AlertRule.objects.get(id=alert_rule_id)
                self.stdout.write(f'Using alert rule: {alert_rule.name}')
            
            alert_service = AlertService()
            alerts = alert_service.send_critical_vulnerability_alert(vulnerability, alert_rule)
            
            if alerts:
                self.stdout.write(
                    self.style.SUCCESS(f'\n✓ Successfully sent {len(alerts)} alert(s)')
                )
                for alert in alerts:
                    self.stdout.write(f'  - {alert.channel}: {alert.status}')
                    if alert.external_ticket_id:
                        self.stdout.write(f'    Ticket ID: {alert.external_ticket_id}')
                        self.stdout.write(f'    Ticket URL: {alert.external_ticket_url}')
            else:
                self.stdout.write(
                    self.style.WARNING('\n⚠ No alerts were sent. Check alert rule configuration.')
                )
                
        except Vulnerability.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'✗ Vulnerability with ID {vulnerability_id} not found')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'✗ Error: {str(e)}')
            )

