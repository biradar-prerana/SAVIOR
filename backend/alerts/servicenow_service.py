"""
ServiceNow integration service for creating tickets
"""
import requests
import base64
import logging

logger = logging.getLogger(__name__)


class ServiceNowService:
    """Service for creating ServiceNow tickets"""
    
    def __init__(self, instance_url, username, password, table_name='incident'):
        """
        Initialize ServiceNow service
        
        Args:
            instance_url: ServiceNow instance URL (e.g., 'https://yourcompany.service-now.com')
            username: ServiceNow username
            password: ServiceNow password
            table_name: ServiceNow table name (default: 'incident')
        """
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.table_name = table_name
        self.api_url = f"{self.instance_url}/api/now/table/{table_name}"
        
        # Create basic auth header
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        self.headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def create_vulnerability_ticket(self, vulnerability, urgency='1', impact='1'):
        """
        Create ServiceNow ticket for vulnerability
        
        Args:
            vulnerability: Vulnerability instance
            urgency: ServiceNow urgency (1=Critical, 2=High, 3=Medium, 4=Low)
            impact: ServiceNow impact (1=Critical, 2=High, 3=Medium, 4=Low)
        
        Returns:
            Dictionary with ticket_id and ticket_url, or None on failure
        """
        try:
            # Get risk score if available
            risk_score = None
            if hasattr(vulnerability, 'risk_score') and vulnerability.risk_score:
                risk_score = vulnerability.risk_score.overall_score
            
            # Map severity to urgency/impact
            severity_map = {
                'critical': ('1', '1'),
                'high': ('2', '2'),
                'medium': ('3', '3'),
                'low': ('4', '4'),
            }
            urgency, impact = severity_map.get(vulnerability.severity.lower(), (urgency, impact))
            
            # Build description
            description = self._build_description(vulnerability, risk_score)
            
            # Prepare ticket data
            ticket_data = {
                "short_description": f"Security Vulnerability: {vulnerability.title}",
                "description": description,
                "urgency": urgency,
                "impact": impact,
                "category": "Security",
                "subcategory": "Vulnerability",
                "work_notes": f"CVE ID: {vulnerability.cve_id or 'N/A'}\n"
                             f"CVSS Score: {vulnerability.cvss_score or 'N/A'}\n"
                             f"Affected Asset: {vulnerability.location or 'N/A'}",
            }
            
            # Add CVE ID to additional fields if available
            if vulnerability.cve_id:
                ticket_data["comments"] = f"CVE: {vulnerability.cve_id}"
            
            # Create ticket via ServiceNow API
            response = requests.post(
                self.api_url,
                json=ticket_data,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                ticket_info = response.json().get('result', {})
                ticket_id = ticket_info.get('number')
                ticket_url = f"{self.instance_url}/nav_to.do?uri={self.table_name}.do?sys_id={ticket_info.get('sys_id')}"
                
                logger.info(f"ServiceNow ticket created: {ticket_id}")
                return {
                    'ticket_id': ticket_id,
                    'ticket_url': ticket_url,
                    'ticket_data': ticket_info
                }
            else:
                logger.error(f"Failed to create ServiceNow ticket: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating ServiceNow ticket: {str(e)}")
            return None
    
    def _build_description(self, vulnerability, risk_score=None):
        """Build ServiceNow ticket description"""
        description_parts = [
            f"Severity: {vulnerability.severity.upper()}",
            f"CVE ID: {vulnerability.cve_id or 'N/A'}",
            f"CVSS Score: {vulnerability.cvss_score or 'N/A'}",
        ]
        
        if risk_score:
            description_parts.append(f"AI Risk Score: {risk_score:.1f}/100")
        
        description_parts.extend([
            f"Affected Asset: {vulnerability.location or 'N/A'}",
            f"Vulnerability Type: {vulnerability.vulnerability_type or 'N/A'}",
            "",
            "Description:",
            vulnerability.description or 'No description available',
        ])
        
        if vulnerability.recommendation:
            description_parts.extend([
                "",
                "Remediation:",
                vulnerability.recommendation
            ])
        
        if vulnerability.remediation_steps:
            description_parts.extend([
                "",
                "Remediation Steps:"
            ])
            for idx, step in enumerate(vulnerability.remediation_steps, 1):
                description_parts.append(f"{idx}. {step}")
        
        return "\n\n".join(description_parts)
    
    def test_connection(self):
        """Test ServiceNow connection"""
        try:
            response = requests.get(
                f"{self.instance_url}/api/now/table/sys_user",
                headers=self.headers,
                params={"sysparm_limit": 1},
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"ServiceNow connection test failed: {str(e)}")
            return False

