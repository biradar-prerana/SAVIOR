"""
Scanning models for vulnerability detection
"""
from django.db import models
from django.conf import settings

User = settings.AUTH_USER_MODEL


class ScanTarget(models.Model):
    """Represents a target to be scanned"""
    SCAN_TYPES = [
        ('web', 'Web Application'),
        ('network', 'Network'),
        ('api', 'API'),
        ('code', 'Source Code'),
        ('container', 'Container'),
    ]
    
    name = models.CharField(max_length=255)
    target_url = models.URLField(blank=True, null=True)
    target_type = models.CharField(max_length=50, choices=SCAN_TYPES)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.target_type})"


class Scan(models.Model):
    """Represents a vulnerability scan"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scan_type = models.CharField(max_length=50)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_config = models.JSONField(default=dict)  # Flexible scan configuration
    error_message = models.TextField(blank=True, null=True)
    
    # Scan results and history
    scan_results = models.JSONField(default=dict)  # Raw scan results
    scan_summary = models.JSONField(default=dict)  # Summary statistics
    total_vulnerabilities = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    # Scan execution details
    scan_duration = models.FloatField(null=True, blank=True)  # Duration in seconds
    scanner_version = models.CharField(max_length=50, blank=True)
    scan_engine = models.CharField(max_length=100, blank=True)  # Tool used
    
    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['target', '-started_at']),
            models.Index(fields=['status', '-started_at']),
            models.Index(fields=['initiated_by', '-started_at']),
            models.Index(fields=['scan_type', '-started_at']),
            models.Index(fields=['completed_at']),
        ]
    
    def __str__(self):
        return f"Scan {self.id} - {self.target.name} ({self.status})"
    
    def update_summary(self):
        """Update scan summary statistics"""
        from django.db.models import Count, Q
        
        stats = self.vulnerabilities.aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low')),
            info=Count('id', filter=Q(severity='info'))
        )
        
        self.total_vulnerabilities = stats['total']
        self.critical_count = stats['critical']
        self.high_count = stats['high']
        self.medium_count = stats['medium']
        self.low_count = stats['low']
        self.info_count = stats['info']
        # Use update_fields to prevent signal recursion
        self.save(update_fields=['total_vulnerabilities', 'critical_count', 'high_count', 
                                'medium_count', 'low_count', 'info_count'])


class Vulnerability(models.Model):
    """Represents a detected vulnerability"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cve_id = models.CharField(max_length=50, blank=True, null=True, db_index=True)
    cve_data = models.ForeignKey('scanning.CVEData', on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities')
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True)
    location = models.CharField(max_length=500)  # URL, file path, etc.
    evidence = models.JSONField(default=dict)  # Evidence data
    recommendation = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_false_positive = models.BooleanField(default=False)
    
    # Additional vulnerability metadata
    vulnerability_type = models.CharField(max_length=100, blank=True)  # SQL Injection, XSS, etc.
    affected_component = models.CharField(max_length=500, blank=True)
    remediation_steps = models.JSONField(default=list)  # Step-by-step remediation
    references = models.JSONField(default=list)  # Reference links
    tags = models.JSONField(default=list)  # Tags for categorization
    
    # Scan history tracking
    first_detected = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    detection_count = models.IntegerField(default=1)  # How many times detected
    
    class Meta:
        ordering = ['-severity', '-cvss_score']
        verbose_name_plural = 'Vulnerabilities'
        indexes = [
            models.Index(fields=['scan', '-detected_at']),
            models.Index(fields=['severity', '-cvss_score']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['is_false_positive', '-detected_at']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.severity})"
    
    def link_cve_data(self):
        """Link CVE data if cve_id is available"""
        if self.cve_id and not self.cve_data:
            try:
                from .cve_models import CVEData
                cve = CVEData.objects.filter(cve_id=self.cve_id).first()
                if cve:
                    self.cve_data = cve
                    if not self.cvss_score and cve.cvss_v3_score:
                        self.cvss_score = cve.cvss_v3_score
                    if not self.cvss_vector and cve.cvss_v3_vector:
                        self.cvss_vector = cve.cvss_v3_vector
                    self.save()
            except Exception:
                pass

