"""
Serializers for scanning module
"""
from rest_framework import serializers
from django.conf import settings
from .models import ScanTarget, Scan, Vulnerability

User = settings.AUTH_USER_MODEL


class ScanTargetSerializer(serializers.ModelSerializer):
    """Serializer for ScanTarget"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = ScanTarget
        fields = ['id', 'name', 'target_url', 'target_type', 'description',
                  'created_by', 'created_by_username', 'created_at', 'updated_at', 'is_active']
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan"""
    target_name = serializers.CharField(source='target.name', read_only=True)
    initiated_by_username = serializers.CharField(source='initiated_by.username', read_only=True)
    vulnerability_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = ['id', 'target', 'target_name', 'status', 'scan_type', 'started_at',
                  'completed_at', 'initiated_by', 'initiated_by_username', 'scan_config',
                  'error_message', 'vulnerability_count']
        read_only_fields = ['initiated_by', 'started_at', 'completed_at']
    
    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count()


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for Vulnerability"""
    scan_target_name = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    
    class Meta:
        model = Vulnerability
        fields = ['id', 'scan', 'scan_target_name', 'title', 'description', 'severity',
                  'cve_id', 'cvss_score', 'cvss_vector', 'location', 'evidence', 'recommendation',
                  'vulnerability_type', 'affected_component', 'remediation_steps', 'references',
                  'detected_at', 'is_false_positive', 'risk_score']
        read_only_fields = ['detected_at']
    
    def get_scan_target_name(self, obj):
        """Get target name safely"""
        try:
            if hasattr(obj, 'scan') and obj.scan and hasattr(obj.scan, 'target') and obj.scan.target:
                return obj.scan.target.name
        except Exception:
            pass
        return None
    
    def get_risk_score(self, obj):
        """Get risk score if available"""
        try:
            if hasattr(obj, 'risk_score') and obj.risk_score:
                return {
                    'overall_score': obj.risk_score.overall_score,
                    'exploitability_score': obj.risk_score.exploitability_score,
                    'impact_score': obj.risk_score.impact_score,
                    'confidence': obj.risk_score.confidence,
                    'ai_model_version': obj.risk_score.ai_model_version,
                    'predicted_exploit_likelihood': obj.risk_score.predicted_exploit_likelihood,
                    'remediation_priority': obj.risk_score.remediation_priority,
                }
        except Exception:
            pass
        return None


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating a new scan"""
    target_id = serializers.IntegerField()
    scan_type = serializers.CharField()
    scan_config = serializers.DictField(required=False, default=dict)

