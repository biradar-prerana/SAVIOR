"""
Admin configuration for AI Risk Scoring module
"""
from django.contrib import admin
from .models import RiskScore, RiskAssessment, AIModel


@admin.register(RiskScore)
class RiskScoreAdmin(admin.ModelAdmin):
    list_display = ['vulnerability', 'overall_score', 'exploitability_score', 'impact_score', 'confidence', 'generated_at']
    list_filter = ['ai_model_version', 'generated_at']
    search_fields = ['vulnerability__title']


@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'overall_risk', 'risk_score', 'vulnerability_count', 'generated_at']
    list_filter = ['overall_risk', 'generated_at']
    search_fields = ['scan__target__name']


@admin.register(AIModel)
class AIModelAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'model_type', 'is_active', 'created_at']
    list_filter = ['model_type', 'is_active', 'created_at']

