"""
CVE (Common Vulnerabilities and Exposures) data models for MongoDB
"""
from django.db import models
from pymongo import IndexModel, ASCENDING, DESCENDING
from savior_backend.mongodb import mongodb_connection


class CVEData(models.Model):
    """CVE information stored in MongoDB"""
    
    cve_id = models.CharField(max_length=50, unique=True, db_index=True)
    description = models.TextField()
    cvss_v2_score = models.FloatField(null=True, blank=True)
    cvss_v2_vector = models.CharField(max_length=200, blank=True)
    cvss_v3_score = models.FloatField(null=True, blank=True)
    cvss_v3_vector = models.CharField(max_length=200, blank=True)
    cvss_v31_score = models.FloatField(null=True, blank=True)
    cvss_v31_vector = models.CharField(max_length=200, blank=True)
    
    # CVE metadata
    published_date = models.DateTimeField(null=True, blank=True)
    modified_date = models.DateTimeField(null=True, blank=True)
    severity = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None'),
    ], blank=True)
    
    # Affected products/software
    affected_products = models.JSONField(default=list)  # List of affected software
    cpe_list = models.JSONField(default=list)  # Common Platform Enumeration

    # References and links
    references = models.JSONField(default=list)  # List of reference URLs
    vendor_advisory = models.URLField(blank=True, null=True)
    
    # Additional metadata
    cwe_id = models.CharField(max_length=20, blank=True)  # Common Weakness Enumeration
    exploit_available = models.BooleanField(default=False)
    patch_available = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict)  # Additional flexible data
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-published_date', '-cvss_v3_score']
        indexes = [
            models.Index(fields=['cve_id']),
            models.Index(fields=['severity', '-cvss_v3_score']),
            models.Index(fields=['published_date']),
        ]
    
    def __str__(self):
        return f"{self.cve_id} - {self.severity}"
    
    @classmethod
    def create_indexes(cls):
        """Create MongoDB indexes for performance"""
        try:
            collection = mongodb_connection.get_collection('scanning_cvedata')
            
            indexes = [
                IndexModel([('cve_id', ASCENDING)], unique=True, name='cve_id_unique'),
                IndexModel([('severity', ASCENDING), ('cvss_v3_score', DESCENDING)], name='severity_score_idx'),
                IndexModel([('published_date', DESCENDING)], name='published_date_idx'),
                IndexModel([('cvss_v3_score', DESCENDING)], name='cvss_v3_score_idx'),
                IndexModel([('exploit_available', ASCENDING)], name='exploit_available_idx'),
            ]
            
            collection.create_indexes(indexes)
            return True
        except Exception as e:
            print(f"Error creating CVE indexes: {str(e)}")
            return False


class CVEHistory(models.Model):
    """Historical tracking of CVE data changes"""
    
    cve = models.ForeignKey(CVEData, on_delete=models.CASCADE, related_name='history')
    change_type = models.CharField(max_length=50, choices=[
        ('created', 'Created'),
        ('updated', 'Updated'),
        ('score_changed', 'Score Changed'),
        ('severity_changed', 'Severity Changed'),
    ])
    old_data = models.JSONField(default=dict)
    new_data = models.JSONField(default=dict)
    changed_by = models.CharField(max_length=100, blank=True)  # System or user
    changed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-changed_at']
    
    def __str__(self):
        return f"{self.cve.cve_id} - {self.change_type} at {self.changed_at}"

