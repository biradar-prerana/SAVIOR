"""
MongoDB index creation for scanning models
"""
from savior_backend.mongodb import mongodb_connection
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT
import logging

logger = logging.getLogger(__name__)


def create_scan_indexes():
    """Create indexes for Scan collection"""
    try:
        collection = mongodb_connection.get_collection('scanning_scan')
        
        indexes = [
            IndexModel([('target_id', ASCENDING), ('started_at', DESCENDING)], name='target_started_idx'),
            IndexModel([('status', ASCENDING), ('started_at', DESCENDING)], name='status_started_idx'),
            IndexModel([('initiated_by_id', ASCENDING), ('started_at', DESCENDING)], name='user_started_idx'),
            IndexModel([('completed_at', DESCENDING)], name='completed_at_idx'),
            IndexModel([('scan_type', ASCENDING)], name='scan_type_idx'),
        ]
        
        collection.create_indexes(indexes)
        logger.info("Created indexes for Scan collection")
        return True
    except Exception as e:
        logger.error(f"Error creating Scan indexes: {str(e)}")
        return False


def create_vulnerability_indexes():
    """Create indexes for Vulnerability collection"""
    try:
        collection = mongodb_connection.get_collection('scanning_vulnerability')
        
        indexes = [
            IndexModel([('scan_id', ASCENDING), ('detected_at', DESCENDING)], name='scan_detected_idx'),
            IndexModel([('severity', ASCENDING), ('cvss_score', DESCENDING)], name='severity_cvss_idx'),
            IndexModel([('cve_id', ASCENDING)], name='cve_id_idx'),
            IndexModel([('is_false_positive', ASCENDING), ('detected_at', DESCENDING)], name='false_positive_idx'),
            IndexModel([('vulnerability_type', ASCENDING)], name='vuln_type_idx'),
            IndexModel([('title', TEXT)], name='title_text_idx'),
        ]
        
        collection.create_indexes(indexes)
        logger.info("Created indexes for Vulnerability collection")
        return True
    except Exception as e:
        logger.error(f"Error creating Vulnerability indexes: {str(e)}")
        return False


def create_cve_indexes():
    """Create indexes for CVE collection"""
    try:
        collection = mongodb_connection.get_collection('scanning_cvedata')
        
        indexes = [
            IndexModel([('cve_id', ASCENDING)], unique=True, name='cve_id_unique'),
            IndexModel([('severity', ASCENDING), ('cvss_v3_score', DESCENDING)], name='severity_score_idx'),
            IndexModel([('published_date', DESCENDING)], name='published_date_idx'),
            IndexModel([('cvss_v3_score', DESCENDING)], name='cvss_v3_score_idx'),
            IndexModel([('exploit_available', ASCENDING)], name='exploit_available_idx'),
            IndexModel([('cwe_id', ASCENDING)], name='cwe_id_idx'),
        ]
        
        collection.create_indexes(indexes)
        logger.info("Created indexes for CVE collection")
        return True
    except Exception as e:
        logger.error(f"Error creating CVE indexes: {str(e)}")
        return False


def create_all_indexes():
    """Create all MongoDB indexes"""
    results = {
        'scan': create_scan_indexes(),
        'vulnerability': create_vulnerability_indexes(),
        'cve': create_cve_indexes(),
    }
    return results

