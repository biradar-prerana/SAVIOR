"""
Admin configuration for reporting module
"""
from django.contrib import admin
from .models import Report, ReportTemplate, ReportSchedule


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['name', 'report_type', 'format', 'generated_by', 'generated_at']
    list_filter = ['report_type', 'format', 'generated_at']
    search_fields = ['name']


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'template_type', 'format', 'is_default', 'created_by', 'created_at']
    list_filter = ['template_type', 'format', 'is_default', 'created_at']


@admin.register(ReportSchedule)
class ReportScheduleAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'schedule_type', 'is_active', 'last_run', 'next_run']
    list_filter = ['schedule_type', 'is_active', 'last_run']

