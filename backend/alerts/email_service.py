"""
Email alert service for sending vulnerability notifications
"""
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


class EmailAlertService:
    """Service for sending email alerts"""
    
    def __init__(self):
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@savior.com')
        self.site_name = getattr(settings, 'SITE_NAME', 'SAVIOR')
    
    def send_critical_vulnerability_alert(self, vulnerability, recipients):
        """
        Send email alert for critical vulnerability
        
        Args:
            vulnerability: Vulnerability instance
            recipients: List of email addresses
        
        Returns:
            Boolean indicating success
        """
        try:
            # Get risk score if available
            risk_score = None
            if hasattr(vulnerability, 'risk_score') and vulnerability.risk_score:
                risk_score = vulnerability.risk_score.overall_score
            
            # Prepare context
            context = {
                'vulnerability': vulnerability,
                'risk_score': risk_score,
                'site_name': self.site_name,
                'severity': vulnerability.severity.upper(),
            }
            
            # Generate email content
            subject = f"[{self.site_name}] Critical Vulnerability Alert: {vulnerability.title}"
            
            # HTML content
            html_message = render_to_string('alerts/critical_vulnerability_email.html', context)
            
            # Plain text content
            text_message = strip_tags(html_message)
            
            # Send email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_message,
                from_email=self.from_email,
                to=recipients,
            )
            email.attach_alternative(html_message, "text/html")
            email.send()
            
            logger.info(f"Critical vulnerability alert sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            return False
    
    def send_anomaly_alert(self, anomaly, recipients):
        """
        Send email alert for detected anomaly
        """
        try:
            subject = f"[{self.site_name}] Anomaly Detected: {anomaly.title}"
            # Minimal HTML message, no external template dependency
            html_message = (
                f"<h2>Anomaly Detected</h2>"
                f"<p><strong>Type:</strong> {anomaly.anomaly_type}</p>"
                f"<p><strong>Severity:</strong> {anomaly.severity.upper()}</p>"
                f"<p><strong>Details:</strong> {anomaly.description or ''}</p>"
                f"<p><strong>Detected At:</strong> {getattr(anomaly, 'detected_at', '')}</p>"
                f"<p>This is an automated alert from {self.site_name}.</p>"
            )
            text_message = strip_tags(html_message)
            
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_message,
                from_email=self.from_email,
                to=recipients,
            )
            email.attach_alternative(html_message, "text/html")
            email.send()
            return True
        except Exception as e:
            logger.error(f"Error sending anomaly email alert: {str(e)}")
            return False
    
    def send_vulnerability_summary(self, vulnerabilities, recipients, scan=None):
        """
        Send summary email for multiple vulnerabilities
        
        Args:
            vulnerabilities: QuerySet or list of Vulnerability objects
            recipients: List of email addresses
            scan: Optional Scan instance
        
        Returns:
            Boolean indicating success
        """
        try:
            context = {
                'vulnerabilities': vulnerabilities,
                'scan': scan,
                'site_name': self.site_name,
                'total_count': len(vulnerabilities),
                'critical_count': sum(1 for v in vulnerabilities if v.severity == 'critical'),
                'high_count': sum(1 for v in vulnerabilities if v.severity == 'high'),
            }
            
            subject = f"[{self.site_name}] Vulnerability Scan Summary - {context['critical_count']} Critical Issues"
            
            html_message = render_to_string('alerts/vulnerability_summary_email.html', context)
            text_message = strip_tags(html_message)
            
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_message,
                from_email=self.from_email,
                to=recipients,
            )
            email.attach_alternative(html_message, "text/html")
            email.send()
            
            logger.info(f"Vulnerability summary sent to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Error sending summary email: {str(e)}")
            return False

