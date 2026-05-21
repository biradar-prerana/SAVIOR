"""
Lightweight SMS alert service using configured webhook integration.
If a WebhookEndpoint is active, it will POST a payload to the URL.
"""
import logging
import requests
from django.conf import settings
from integrations.models import Integration, WebhookEndpoint

logger = logging.getLogger(__name__)


class SmsAlertService:
    """Send SMS via generic webhook integration"""

    def __init__(self):
        self.timeout = getattr(settings, 'SMS_WEBHOOK_TIMEOUT', 10)

    def _get_active_webhook(self):
        """Get an active webhook endpoint suitable for SMS delivery"""
        try:
            integration = Integration.objects.filter(
                integration_type='webhook',
                is_enabled=True,
                status='active'
            ).order_by('-created_at').first()
            if not integration:
                return None
            webhook = WebhookEndpoint.objects.filter(
                integration=integration,
                is_active=True
            ).order_by('-created_at').first()
            return webhook
        except Exception as e:
            logger.error(f"Error fetching webhook endpoint: {str(e)}")
            return None

    def send_sms_alert(self, title: str, message: str, recipients: list[str]) -> bool:
        """
        Send SMS alert via webhook.
        Payload structure is generic; provider should map fields accordingly.
        """
        try:
            webhook = self._get_active_webhook()
            if not webhook:
                logger.warning("No active webhook endpoint configured for SMS delivery")
                return False

            payload = {
                'type': 'sms_alert',
                'title': title,
                'message': message,
                'recipients': recipients
            }
            headers = {'Content-Type': 'application/json'}
            if webhook.headers:
                headers.update(webhook.headers)

            resp = requests.post(webhook.url, json=payload, headers=headers, timeout=self.timeout)
            if 200 <= resp.status_code < 300:
                logger.info(f"SMS alert delivered to {len(recipients)} recipients via webhook")
                return True
            else:
                logger.error(f"SMS webhook responded with {resp.status_code}: {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Error sending SMS alert: {str(e)}")
            return False
