"""
Main alert service for managing vulnerability alerts
"""
from django.utils import timezone
from .models import Alert, AlertRule
from .email_service import EmailAlertService
from .sms_service import SmsAlertService
from .jira_service import JiraService
from .servicenow_service import ServiceNowService
from scanning.models import Vulnerability
from anomaly_detection.models import AnomalyDetection
from integrations.models import Integration
import logging

logger = logging.getLogger(__name__)


class AlertService:
    """Service for managing and sending alerts"""
    
    def __init__(self):
        self.email_service = EmailAlertService()
        self.sms_service = SmsAlertService()
    
    def send_critical_vulnerability_alert(self, vulnerability, alert_rule=None):
        """
        Send alert for critical vulnerability
        
        Args:
            vulnerability: Vulnerability instance
            alert_rule: Optional AlertRule instance
        
        Returns:
            List of Alert instances created
        """
        alerts_created = []
        
        # Get active alert rules if not provided
        if alert_rule is None:
            alert_rules = AlertRule.objects.filter(
                is_active=True,
                severity_threshold__in=['critical', 'high']  # Include high for critical
            )
        else:
            alert_rules = [alert_rule] if alert_rule.is_active else []
        
        # Check if vulnerability meets threshold
        if vulnerability.severity not in ['critical', 'high']:
            return alerts_created
        
        # Fallback: if there are no active rules, still create an in-app alert record
        if not alert_rules:
            alert = Alert.objects.create(
                alert_type='critical_vulnerability',
                status='sent',
                channel='webhook',
                vulnerability=vulnerability,
                scan=vulnerability.scan if hasattr(vulnerability, 'scan') else None,
                target=vulnerability.scan.target if hasattr(vulnerability, 'scan') and vulnerability.scan else None,
                title=f"Critical Vulnerability: {vulnerability.title}",
                message=f"A critical vulnerability has been detected: {vulnerability.title}",
                severity=vulnerability.severity,
                recipients=[],
                sent_at=timezone.now(),
            )
            alerts_created.append(alert)
            return alerts_created
        
        for rule in alert_rules:
            # Check if vulnerability meets rule criteria
            if not self._meets_rule_criteria(vulnerability, rule):
                continue
            
            # Collect recipients
            recipients = list(rule.email_recipients)
            for user in rule.notify_users.all():
                if user.email:
                    recipients.append(user.email)
            
            if not recipients:
                continue
            
            # Send email alert
            if rule.send_email:
                email_sent = self.email_service.send_critical_vulnerability_alert(
                    vulnerability, recipients
                )
                
                alert = Alert.objects.create(
                    alert_type='critical_vulnerability',
                    status='sent' if email_sent else 'failed',
                    channel='email',
                    vulnerability=vulnerability,
                    scan=vulnerability.scan if hasattr(vulnerability, 'scan') else None,
                    target=vulnerability.scan.target if hasattr(vulnerability, 'scan') and vulnerability.scan else None,
                    title=f"Critical Vulnerability: {vulnerability.title}",
                    message=f"A critical vulnerability has been detected: {vulnerability.title}",
                    severity=vulnerability.severity,
                    recipients=recipients,
                    sent_at=timezone.now() if email_sent else None,
                )
                alerts_created.append(alert)
            
            # Create JIRA ticket
            if rule.create_jira_ticket and rule.jira_integration:
                jira_result = self._create_jira_ticket(vulnerability, rule.jira_integration)
                if jira_result:
                    alert = Alert.objects.create(
                        alert_type='critical_vulnerability',
                        status='sent',
                        channel='jira',
                        vulnerability=vulnerability,
                        scan=vulnerability.scan if hasattr(vulnerability, 'scan') else None,
                        title=f"JIRA Ticket Created: {vulnerability.title}",
                        message=f"JIRA ticket created for vulnerability: {vulnerability.title}",
                        severity=vulnerability.severity,
                        integration=rule.jira_integration,
                        external_ticket_id=jira_result.get('ticket_id'),
                        external_ticket_url=jira_result.get('ticket_url'),
                        sent_at=timezone.now(),
                    )
                    alerts_created.append(alert)
            
            # Create ServiceNow ticket
            if rule.create_servicenow_ticket and rule.servicenow_integration:
                servicenow_result = self._create_servicenow_ticket(vulnerability, rule.servicenow_integration)
                if servicenow_result:
                    alert = Alert.objects.create(
                        alert_type='critical_vulnerability',
                        status='sent',
                        channel='servicenow',
                        vulnerability=vulnerability,
                        scan=vulnerability.scan if hasattr(vulnerability, 'scan') else None,
                        title=f"ServiceNow Ticket Created: {vulnerability.title}",
                        message=f"ServiceNow ticket created for vulnerability: {vulnerability.title}",
                        severity=vulnerability.severity,
                        integration=rule.servicenow_integration,
                        external_ticket_id=servicenow_result.get('ticket_id'),
                        external_ticket_url=servicenow_result.get('ticket_url'),
                        sent_at=timezone.now(),
                    )
                    alerts_created.append(alert)
        
        return alerts_created
    
    def send_scan_completed_alert(self, scan, alert_rule=None):
        """
        Send summary alert when a scan completes and has serious findings
        """
        alerts_created = []
        
        # Only alert if serious findings; otherwise send summary if medium/low exist
        serious_count = (scan.critical_count or 0) + (scan.high_count or 0)
        if serious_count <= 0:
            total = (scan.total_vulnerabilities or 0)
            if total > 0:
                alert = Alert.objects.create(
                    alert_type='scan_completed',
                    status='sent',
                    channel='webhook',
                    scan=scan,
                    target=scan.target,
                    title=f"Scan Completed: {scan.target.name}",
                    message=f"Scan completed with {total} findings (Medium: {scan.medium_count or 0}, Low: {scan.low_count or 0}, Info: {scan.info_count or 0}).",
                    severity='medium' if (scan.medium_count or 0) > 0 else 'low',
                    recipients=[],
                    sent_at=timezone.now(),
                )
                alerts_created.append(alert)
            return alerts_created
        
        # Get active alert rules
        if alert_rule is None:
            alert_rules = AlertRule.objects.filter(
                is_active=True,
                severity_threshold__in=['critical', 'high']
            )
        else:
            alert_rules = [alert_rule] if alert_rule.is_active else []
        
        # Collect vulnerabilities for summary
        serious_vulns = Vulnerability.objects.filter(
            scan=scan, severity__in=['critical', 'high']
        )
        
        for rule in alert_rules:
            recipients = list(rule.email_recipients)
            notify_users = list(rule.notify_users.all())
            for user in notify_users:
                if user.email:
                    recipients.append(user.email)
            
            phone_numbers = [u.phone_number for u in notify_users if getattr(u, 'phone_number', None)]
            
            if recipients:
                email_sent = self.email_service.send_vulnerability_summary(serious_vulns, recipients, scan=scan)
                alert = Alert.objects.create(
                    alert_type='scan_completed',
                    status='sent' if email_sent else 'failed',
                    channel='email',
                    scan=scan,
                    target=scan.target,
                    title=f"Scan Completed: {scan.target.name}",
                    message=f"Scan completed with {serious_count} serious findings (Critical: {scan.critical_count or 0}, High: {scan.high_count or 0}).",
                    severity='high' if (scan.critical_count or 0) == 0 else 'critical',
                    recipients=recipients,
                    sent_at=timezone.now() if email_sent else None,
                )
                alerts_created.append(alert)
            
            if phone_numbers:
                sms_sent = self.sms_service.send_sms_alert(
                    title=f"Scan Completed: {scan.target.name}",
                    message=f"Serious findings: Critical {scan.critical_count or 0}, High {scan.high_count or 0}.",
                    recipients=phone_numbers
                )
                alert = Alert.objects.create(
                    alert_type='scan_completed',
                    status='sent' if sms_sent else 'failed',
                    channel='webhook',
                    scan=scan,
                    target=scan.target,
                    title=f"Scan Completed (SMS): {scan.target.name}",
                    message=f"Serious findings: Critical {scan.critical_count or 0}, High {scan.high_count or 0}.",
                    severity='high' if (scan.critical_count or 0) == 0 else 'critical',
                    recipients=phone_numbers,
                    sent_at=timezone.now() if sms_sent else None,
                )
                alerts_created.append(alert)
        
        return alerts_created
    
    def send_anomaly_alert(self, anomaly: AnomalyDetection, alert_rule=None):
        """
        Send alert when an anomaly is detected
        """
        alerts_created = []
        
        # Only send for high/critical anomalies
        if anomaly.severity not in ['critical', 'high']:
            return alerts_created
        
        # Get active alert rules
        if alert_rule is None:
            alert_rules = AlertRule.objects.filter(
                is_active=True,
                severity_threshold__in=['critical', 'high']
            )
        else:
            alert_rules = [alert_rule] if alert_rule.is_active else []
        
        for rule in alert_rules:
            recipients = list(rule.email_recipients)
            notify_users = list(rule.notify_users.all())
            for user in notify_users:
                if user.email:
                    recipients.append(user.email)
            
            phone_numbers = [u.phone_number for u in notify_users if getattr(u, 'phone_number', None)]
            
            title = f"Anomaly Detected: {anomaly.title}"
            message = f"Type: {anomaly.anomaly_type}, Severity: {anomaly.severity}. {anomaly.description or ''}"
            
            if recipients:
                email_sent = self.email_service.send_anomaly_alert(anomaly, recipients)
                alert = Alert.objects.create(
                    alert_type='anomaly',
                    status='sent' if email_sent else 'failed',
                    channel='email',
                    scan=anomaly.scan,
                    target=anomaly.target,
                    title=title,
                    message=message,
                    severity=anomaly.severity,
                    recipients=recipients,
                    sent_at=timezone.now() if email_sent else None,
                )
                alerts_created.append(alert)
            
            if phone_numbers:
                sms_sent = self.sms_service.send_sms_alert(
                    title=title,
                    message=message,
                    recipients=phone_numbers
                )
                alert = Alert.objects.create(
                    alert_type='anomaly',
                    status='sent' if sms_sent else 'failed',
                    channel='webhook',
                    scan=anomaly.scan,
                    target=anomaly.target,
                    title=f"{title} (SMS)",
                    message=message,
                    severity=anomaly.severity,
                    recipients=phone_numbers,
                    sent_at=timezone.now() if sms_sent else None,
                )
                alerts_created.append(alert)
        
        return alerts_created
    
    def _meets_rule_criteria(self, vulnerability, rule):
        """Check if vulnerability meets alert rule criteria"""
        # Check severity threshold
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        vuln_severity_order = severity_order.get(vulnerability.severity.lower(), 5)
        rule_severity_order = severity_order.get(rule.severity_threshold.lower(), 5)
        
        if vuln_severity_order > rule_severity_order:
            return False
        
        # Check risk score threshold
        if rule.risk_score_threshold:
            risk_score = None
            if hasattr(vulnerability, 'risk_score') and vulnerability.risk_score:
                risk_score = vulnerability.risk_score.overall_score
            if not risk_score or risk_score < rule.risk_score_threshold:
                return False
        
        # Check CVE requirement
        if rule.cve_required and not vulnerability.cve_id:
            return False
        
        # Check zero-day only
        if rule.zero_day_only and vulnerability.cve_id:
            return False
        
        return True
    
    def _create_jira_ticket(self, vulnerability, integration):
        """Create JIRA ticket using integration configuration"""
        try:
            config = integration.config
            credentials = integration.credentials
            
            jira_service = JiraService(
                base_url=config.get('base_url', ''),
                username=credentials.get('username', ''),
                api_token=credentials.get('api_token', ''),
                project_key=config.get('project_key', '')
            )
            
            return jira_service.create_vulnerability_ticket(
                vulnerability,
                issue_type=config.get('issue_type', 'Bug'),
                priority=config.get('priority', 'Highest')
            )
        except Exception as e:
            logger.error(f"Error creating JIRA ticket: {str(e)}")
            return None
    
    def _create_servicenow_ticket(self, vulnerability, integration):
        """Create ServiceNow ticket using integration configuration"""
        try:
            config = integration.config
            credentials = integration.credentials
            
            servicenow_service = ServiceNowService(
                instance_url=config.get('instance_url', ''),
                username=credentials.get('username', ''),
                password=credentials.get('password', ''),
                table_name=config.get('table_name', 'incident')
            )
            
            return servicenow_service.create_vulnerability_ticket(
                vulnerability,
                urgency=config.get('urgency', '1'),
                impact=config.get('impact', '1')
            )
        except Exception as e:
            logger.error(f"Error creating ServiceNow ticket: {str(e)}")
            return None

