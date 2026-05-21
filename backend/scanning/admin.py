"""
Admin configuration for scanning module
"""
from django.contrib import admin
from .models import ScanTarget, Scan, Vulnerability
from .cve_models import CVEData, CVEHistory


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'target_type', 'target_url', 'created_by', 'created_at', 'is_active']
    list_filter = ['target_type', 'is_active', 'created_at']
    search_fields = ['name', 'target_url']


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'status', 'scan_type', 'started_at', 'completed_at', 'initiated_by']
    list_filter = ['status', 'scan_type', 'started_at']
    search_fields = ['target__name']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'scan', 'cvss_score', 'detected_at', 'is_false_positive']
    list_filter = ['severity', 'is_false_positive', 'detected_at', 'vulnerability_type']
    search_fields = ['title', 'cve_id', 'description']
    readonly_fields = ['first_detected', 'last_seen']


@admin.register(CVEData)
class CVEDataAdmin(admin.ModelAdmin):
    list_display = ['cve_id', 'severity', 'cvss_v3_score', 'published_date', 'exploit_available']
    list_filter = ['severity', 'exploit_available', 'patch_available', 'published_date']
    search_fields = ['cve_id', 'description', 'cwe_id']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(CVEHistory)
class CVEHistoryAdmin(admin.ModelAdmin):
    list_display = ['cve', 'change_type', 'changed_at', 'changed_by']
    list_filter = ['change_type', 'changed_at']
    search_fields = ['cve__cve_id']
    readonly_fields = ['changed_at']

