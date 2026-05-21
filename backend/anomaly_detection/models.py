"""
Anomaly Detection models
"""
from django.db import models
from django.conf import settings
from django.db import models
from scanning.models import Vulnerability, Scan, ScanTarget

User = settings.AUTH_USER_MODEL


class AnomalyDetection(models.Model):
    """Detected anomalies in the system"""
    
    ANOMALY_TYPES = [
        ('system_behavior', 'Unusual System Behavior'),
        ('configuration_drift', 'Configuration Drift'),
        ('unknown_threat', 'Unknown Threat'),
        ('zero_day', 'Potential Zero-Day Vulnerability'),
        ('scan_anomaly', 'Scan Anomaly'),
        ('vulnerability_pattern', 'Unusual Vulnerability Pattern'),
        ('network_anomaly', 'Network Behavior Anomaly'),
        ('log_anomaly', 'System Log Anomaly'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ]
    
    anomaly_type = models.CharField(max_length=50, choices=ANOMALY_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # Related entities
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, 
        related_name='anomalies', null=True, blank=True
    )
    scan = models.ForeignKey(
        Scan, on_delete=models.CASCADE,
        related_name='anomalies', null=True, blank=True
    )
    target = models.ForeignKey(
        ScanTarget, on_delete=models.CASCADE,
        related_name='anomalies', null=True, blank=True
    )
    
    # Anomaly details
    title = models.CharField(max_length=500)
    description = models.TextField()
    anomaly_score = models.FloatField()  # Isolation Forest anomaly score (-1 to 1)
    confidence = models.FloatField()  # 0-1
    
    # Feature data that triggered the anomaly
    feature_vector = models.JSONField(default=dict)  # Features used for detection
    anomaly_factors = models.JSONField(default=dict)  # What made it anomalous
    
    # Zero-day specific fields
    is_potential_zero_day = models.BooleanField(default=False)
    has_no_cve = models.BooleanField(default=False)  # No CVE assigned
    unusual_pattern = models.TextField(blank=True)  # Description of unusual pattern
    
    # Configuration drift specific
    baseline_config = models.JSONField(default=dict)  # Expected configuration
    current_config = models.JSONField(default=dict)  # Current configuration
    drift_details = models.JSONField(default=dict)  # What changed
    
    # Detection metadata
    detected_at = models.DateTimeField(auto_now_add=True)
    detected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    model_version = models.CharField(max_length=50, blank=True)
    
    # Investigation and resolution
    investigated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, 
        related_name='investigated_anomalies', null=True, blank=True
    )
    investigation_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-anomaly_score', '-detected_at']
        indexes = [
            models.Index(fields=['anomaly_type', '-detected_at']),
            models.Index(fields=['severity', '-anomaly_score']),
            models.Index(fields=['status', '-detected_at']),
            models.Index(fields=['is_potential_zero_day', '-anomaly_score']),
            models.Index(fields=['vulnerability', '-detected_at']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.anomaly_type}) - Score: {self.anomaly_score:.3f}"


class AnomalyModel(models.Model):
    """Isolation Forest model for anomaly detection"""
    
    MODEL_TYPES = [
        ('vulnerability', 'Vulnerability Anomaly Detection'),
        ('system_behavior', 'System Behavior Anomaly Detection'),
        ('configuration', 'Configuration Drift Detection'),
        ('zero_day', 'Zero-Day Detection'),
    ]
    
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50)
    model_type = models.CharField(max_length=50, choices=MODEL_TYPES)
    is_active = models.BooleanField(default=True)
    
    # Model configuration
    config = models.JSONField(default=dict)  # Isolation Forest parameters
    performance_metrics = models.JSONField(default=dict)  # Model performance
    model_file_path = models.CharField(max_length=500, blank=True)
    
    # Training data
    training_samples = models.IntegerField(default=0)
    contamination = models.FloatField(default=0.1)  # Expected proportion of anomalies
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['name', 'version']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} v{self.version} ({self.model_type})"


class AnomalyBaseline(models.Model):
    """Baseline configurations and patterns for anomaly detection"""
    
    BASELINE_TYPES = [
        ('system_config', 'System Configuration'),
        ('scan_pattern', 'Scan Pattern'),
        ('vulnerability_pattern', 'Vulnerability Pattern'),
        ('network_behavior', 'Network Behavior'),
    ]
    
    name = models.CharField(max_length=255)
    baseline_type = models.CharField(max_length=50, choices=BASELINE_TYPES)
    target = models.ForeignKey(
        ScanTarget, on_delete=models.CASCADE,
        related_name='baselines', null=True, blank=True
    )
    
    # Baseline data
    baseline_data = models.JSONField(default=dict)  # Expected patterns/values
    feature_weights = models.JSONField(default=dict)  # Feature importance
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.baseline_type})"

