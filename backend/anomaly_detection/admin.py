"""
Admin configuration for anomaly detection module
"""
from django.contrib import admin
from .models import AnomalyDetection, AnomalyModel, AnomalyBaseline


@admin.register(AnomalyDetection)
class AnomalyDetectionAdmin(admin.ModelAdmin):
    list_display = ['title', 'anomaly_type', 'severity', 'status', 'anomaly_score', 
                   'is_potential_zero_day', 'detected_at']
    list_filter = ['anomaly_type', 'severity', 'status', 'is_potential_zero_day', 'detected_at']
    search_fields = ['title', 'description', 'vulnerability__title']
    readonly_fields = ['detected_at', 'resolved_at']


@admin.register(AnomalyModel)
class AnomalyModelAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'model_type', 'is_active', 'contamination', 
                   'training_samples', 'created_at']
    list_filter = ['model_type', 'is_active', 'created_at']
    search_fields = ['name', 'version']


@admin.register(AnomalyBaseline)
class AnomalyBaselineAdmin(admin.ModelAdmin):
    list_display = ['name', 'baseline_type', 'target', 'is_active', 'created_by', 'created_at']
    list_filter = ['baseline_type', 'is_active', 'created_at']
    search_fields = ['name', 'target__name']

