"""
JIRA integration service for creating tickets
"""
import requests
import logging

logger = logging.getLogger(__name__)


class JiraService:
    """Service for creating JIRA tickets"""
    
    def __init__(self, base_url, username, api_token, project_key):
        """
        Initialize JIRA service
        
        Args:
            base_url: JIRA instance URL (e.g., 'https://yourcompany.atlassian.net')
            username: JIRA username or email
            api_token: JIRA API token
            project_key: JIRA project key (e.g., 'SEC')
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        self.api_url = f"{self.base_url}/rest/api/3"
    
    def create_vulnerability_ticket(self, vulnerability, issue_type='Bug', priority='Highest'):
        """
        Create JIRA ticket for vulnerability
        
        Args:
            vulnerability: Vulnerability instance
            issue_type: JIRA issue type (default: 'Bug')
            priority: JIRA priority (default: 'Highest')
        
        Returns:
            Dictionary with ticket_id and ticket_url, or None on failure
        """
        try:
            # Get risk score if available
            risk_score = None
            if hasattr(vulnerability, 'risk_score') and vulnerability.risk_score:
                risk_score = vulnerability.risk_score.overall_score
            
            # Prepare ticket data
            description = self._build_description(vulnerability, risk_score)
            
            ticket_data = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": f"Security Vulnerability: {vulnerability.title}",
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": description
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": issue_type},
                    "priority": {"name": priority},
                    "labels": ["security", "vulnerability", vulnerability.severity],
                }
            }
            
            # Add CVE ID if available
            if vulnerability.cve_id:
                ticket_data["fields"]["labels"].append(f"CVE-{vulnerability.cve_id}")
            
            # Create ticket via JIRA API
            response = requests.post(
                f"{self.api_url}/issue",
                json=ticket_data,
                auth=(self.username, self.api_token),
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 201:
                ticket_info = response.json()
                ticket_id = ticket_info.get('key')
                ticket_url = f"{self.base_url}/browse/{ticket_id}"
                
                logger.info(f"JIRA ticket created: {ticket_id}")
                return {
                    'ticket_id': ticket_id,
                    'ticket_url': ticket_url,
                    'ticket_data': ticket_info
                }
            else:
                logger.error(f"Failed to create JIRA ticket: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating JIRA ticket: {str(e)}")
            return None
    
    def _build_description(self, vulnerability, risk_score=None):
        """Build JIRA ticket description"""
        description_parts = [
            f"*Severity:* {vulnerability.severity.upper()}",
            f"*CVE ID:* {vulnerability.cve_id or 'N/A'}",
            f"*CVSS Score:* {vulnerability.cvss_score or 'N/A'}",
        ]
        
        if risk_score:
            description_parts.append(f"*AI Risk Score:* {risk_score:.1f}/100")
        
        description_parts.extend([
            f"*Affected Asset:* {vulnerability.location or 'N/A'}",
            f"*Vulnerability Type:* {vulnerability.vulnerability_type or 'N/A'}",
            "",
            "*Description:*",
            vulnerability.description or 'No description available',
        ])
        
        if vulnerability.recommendation:
            description_parts.extend([
                "",
                "*Remediation:*",
                vulnerability.recommendation
            ])
        
        if vulnerability.remediation_steps:
            description_parts.extend([
                "",
                "*Remediation Steps:*"
            ])
            for idx, step in enumerate(vulnerability.remediation_steps, 1):
                description_parts.append(f"{idx}. {step}")
        
        return "\n".join(description_parts)
    
    def test_connection(self):
        """Test JIRA connection"""
        try:
            response = requests.get(
                f"{self.api_url}/myself",
                auth=(self.username, self.api_token),
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"JIRA connection test failed: {str(e)}")
            return False

