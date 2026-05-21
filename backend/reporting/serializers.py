"""
Serializers for reporting module
"""
from rest_framework import serializers
from .models import Report, ReportTemplate, ReportSchedule
from scanning.serializers import ScanSerializer, ScanTargetSerializer


class ReportSerializer(serializers.ModelSerializer):
    """Serializer for Report"""
    generated_by_username = serializers.CharField(source='generated_by.username', read_only=True)
    scan_data = ScanSerializer(source='scan', read_only=True)
    target_data = ScanTargetSerializer(source='target', read_only=True)
    
    class Meta:
        model = Report
        fields = ['id', 'name', 'report_type', 'format', 'scan', 'target', 'scan_data',
                  'target_data', 'generated_by', 'generated_by_username', 'generated_at',
                  'file_path', 'report_data', 'is_scheduled', 'schedule_config']
        read_only_fields = ['generated_by', 'generated_at']


class ReportTemplateSerializer(serializers.ModelSerializer):
    """Serializer for ReportTemplate"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = ReportTemplate
        fields = ['id', 'name', 'description', 'template_type', 'format', 'template_content',
                  'is_default', 'created_by', 'created_by_username', 'created_at', 'updated_at']
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class ReportScheduleSerializer(serializers.ModelSerializer):
    """Serializer for ReportSchedule"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    target_name = serializers.CharField(source='target.name', read_only=True)
    template_name = serializers.CharField(source='template.name', read_only=True)
    
    class Meta:
        model = ReportSchedule
        fields = ['id', 'name', 'target', 'target_name', 'template', 'template_name',
                  'schedule_type', 'schedule_config', 'is_active', 'created_by',
                  'created_by_username', 'created_at', 'last_run', 'next_run']
        read_only_fields = ['created_by', 'created_at', 'last_run']

