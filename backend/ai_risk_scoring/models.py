"""
AI Risk Scoring models
"""
from django.db import models
from django.conf import settings
from django.db import models
from scanning.models import Vulnerability, Scan

User = settings.AUTH_USER_MODEL


class RiskScore(models.Model):
    """AI-generated risk score for a vulnerability"""
    vulnerability = models.OneToOneField(Vulnerability, on_delete=models.CASCADE, related_name='risk_score')
    overall_score = models.FloatField()  # 0-100
    exploitability_score = models.FloatField()  # 0-100
    impact_score = models.FloatField()  # 0-100
    business_impact_score = models.FloatField(null=True, blank=True)  # 0-100
    ai_model_version = models.CharField(max_length=50, default='v1.0')
    confidence = models.FloatField()  # 0-1
    factors = models.JSONField(default=dict)  # AI reasoning factors
    generated_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Additional AI analysis data
    ai_analysis = models.JSONField(default=dict)  # Detailed AI analysis
    risk_trend = models.CharField(max_length=20, choices=[
        ('increasing', 'Increasing'),
        ('stable', 'Stable'),
        ('decreasing', 'Decreasing'),
    ], blank=True)
    predicted_exploit_likelihood = models.FloatField(null=True, blank=True)  # 0-1
    remediation_priority = models.IntegerField(default=0)  # 0-100, higher = more urgent
    
    class Meta:
        ordering = ['-overall_score']
        indexes = [
            models.Index(fields=['vulnerability']),
            models.Index(fields=['-overall_score']),
            models.Index(fields=['remediation_priority', '-overall_score']),
        ]
    
    def __str__(self):
        return f"Risk Score: {self.overall_score} for {self.vulnerability.title}"


class RiskAssessment(models.Model):
    """Overall risk assessment for a scan or target"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='risk_assessments', null=True, blank=True)
    target = models.ForeignKey('scanning.ScanTarget', on_delete=models.CASCADE, related_name='risk_assessments', null=True, blank=True)
    overall_risk = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('minimal', 'Minimal'),
    ])
    risk_score = models.FloatField()  # 0-100
    vulnerability_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    ai_insights = models.JSONField(default=dict)  # AI-generated insights
    recommendations = models.JSONField(default=list)  # Prioritized recommendations
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['scan', '-generated_at']),
            models.Index(fields=['target', '-generated_at']),
            models.Index(fields=['overall_risk', '-generated_at']),
        ]
    
    def __str__(self):
        return f"Risk Assessment: {self.overall_risk} (Score: {self.risk_score})"


class AIModel(models.Model):
    """AI model metadata and configuration"""
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50)
    model_type = models.CharField(max_length=50)  # e.g., 'risk_scoring', 'vulnerability_classification'
    is_active = models.BooleanField(default=True)
    config = models.JSONField(default=dict)  # Model configuration
    performance_metrics = models.JSONField(default=dict)  # Accuracy, precision, etc.
    model_file_path = models.CharField(max_length=500, blank=True)  # Path to saved model file
    training_samples = models.IntegerField(default=0)  # Number of samples used for training
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['name', 'version']
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['model_type', 'is_active']),
            models.Index(fields=['-created_at']),
        ]
    
    def __str__(self):
        return f"{self.name} v{self.version}"

