"""
Utilities for CVE data operations
"""
from .cve_models import CVEData
from savior_backend.mongodb import mongodb_connection
import logging

logger = logging.getLogger(__name__)


def get_or_create_cve(cve_id, cve_data=None):
    """
    Get or create CVE data entry
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2023-1234')
        cve_data: Optional dict with CVE information
    
    Returns:
        CVEData instance
    """
    try:
        cve, created = CVEData.objects.get_or_create(
            cve_id=cve_id,
            defaults=cve_data or {}
        )
        if created:
            logger.info(f"Created new CVE entry: {cve_id}")
        return cve
    except Exception as e:
        logger.error(f"Error getting/creating CVE {cve_id}: {str(e)}")
        return None


def update_cve_from_api(cve_id, api_data):
    """
    Update CVE data from external API
    
    Args:
        cve_id: CVE identifier
        api_data: Dictionary with CVE data from API
    
    Returns:
        Updated CVEData instance
    """
    try:
        cve = CVEData.objects.filter(cve_id=cve_id).first()
        if not cve:
            cve = CVEData.objects.create(cve_id=cve_id)
        
        # Map API data to model fields
        if 'description' in api_data:
            cve.description = api_data['description']
        if 'cvssV3' in api_data:
            cve.cvss_v3_score = api_data['cvssV3'].get('baseScore')
            cve.cvss_v3_vector = api_data['cvssV3'].get('vectorString', '')
        if 'cvssV2' in api_data:
            cve.cvss_v2_score = api_data['cvssV2'].get('baseScore')
            cve.cvss_v2_vector = api_data['cvssV2'].get('vectorString', '')
        if 'published' in api_data:
            from django.utils.dateparse import parse_datetime
            cve.published_date = parse_datetime(api_data['published'])
        if 'modified' in api_data:
            from django.utils.dateparse import parse_datetime
            cve.modified_date = parse_datetime(api_data['modified'])
        if 'references' in api_data:
            cve.references = api_data['references']
        
        # Determine severity from CVSS score
        if cve.cvss_v3_score:
            if cve.cvss_v3_score >= 9.0:
                cve.severity = 'critical'
            elif cve.cvss_v3_score >= 7.0:
                cve.severity = 'high'
            elif cve.cvss_v3_score >= 4.0:
                cve.severity = 'medium'
            elif cve.cvss_v3_score >= 0.1:
                cve.severity = 'low'
            else:
                cve.severity = 'none'
        
        cve.save()
        logger.info(f"Updated CVE data: {cve_id}")
        return cve
        
    except Exception as e:
        logger.error(f"Error updating CVE {cve_id}: {str(e)}")
        return None


def link_vulnerability_to_cve(vulnerability):
    """
    Link a vulnerability to its CVE data if cve_id is available
    
    Args:
        vulnerability: Vulnerability instance
    """
    if vulnerability.cve_id and not vulnerability.cve_data:
        cve = CVEData.objects.filter(cve_id=vulnerability.cve_id).first()
        if cve:
            vulnerability.cve_data = cve
            if not vulnerability.cvss_score and cve.cvss_v3_score:
                vulnerability.cvss_score = cve.cvss_v3_score
            if not vulnerability.cvss_vector and cve.cvss_v3_vector:
                vulnerability.cvss_vector = cve.cvss_v3_vector
            vulnerability.save()
            logger.info(f"Linked vulnerability {vulnerability.id} to CVE {vulnerability.cve_id}")


def get_cve_statistics():
    """
    Get statistics about CVE data
    
    Returns:
        Dictionary with CVE statistics
    """
    try:
        total = CVEData.objects.count()
        critical = CVEData.objects.filter(severity='critical').count()
        high = CVEData.objects.filter(severity='high').count()
        medium = CVEData.objects.filter(severity='medium').count()
        low = CVEData.objects.filter(severity='low').count()
        with_exploit = CVEData.objects.filter(exploit_available=True).count()
        
        return {
            'total': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'with_exploit': with_exploit,
        }
    except Exception as e:
        logger.error(f"Error getting CVE statistics: {str(e)}")
        return {}

