"""
Reporting models
"""
from django.db import models
from django.conf import settings
from django.db import models
from scanning.models import Scan, ScanTarget

User = settings.AUTH_USER_MODEL


class Report(models.Model):
    """Generated vulnerability report"""
    REPORT_FORMATS = [
        ('pdf', 'PDF'),
        ('html', 'HTML'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
    ]
    
    REPORT_TYPES = [
        ('scan', 'Scan Report'),
        ('target', 'Target Report'),
        ('executive', 'Executive Summary'),
        ('technical', 'Technical Report'),
    ]
    
    name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    format = models.CharField(max_length=20, choices=REPORT_FORMATS, default='pdf')
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    generated_at = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=500, blank=True)  # Path to generated report file
    report_data = models.JSONField(default=dict)  # Report content/data
    is_scheduled = models.BooleanField(default=False)
    schedule_config = models.JSONField(default=dict)  # Schedule configuration
    
    class Meta:
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"{self.name} ({self.report_type})"


class ReportTemplate(models.Model):
    """Report template configuration"""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    template_type = models.CharField(max_length=50)  # e.g., 'executive', 'technical'
    format = models.CharField(max_length=20, choices=Report.REPORT_FORMATS)
    template_content = models.TextField(blank=True)  # Template content or path
    is_default = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class ReportSchedule(models.Model):
    """Scheduled report generation"""
    name = models.CharField(max_length=255)
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scheduled_reports')
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True, blank=True)
    schedule_type = models.CharField(max_length=50, choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('custom', 'Custom'),
    ])
    schedule_config = models.JSONField(default=dict)  # Cron expression or schedule details
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} - {self.schedule_type}"

