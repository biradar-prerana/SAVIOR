"""
Serializers for AI Risk Scoring module
"""
from rest_framework import serializers
from .models import RiskScore, RiskAssessment, AIModel
from scanning.serializers import VulnerabilitySerializer


class RiskScoreSerializer(serializers.ModelSerializer):
    """Serializer for RiskScore"""
    vulnerability = VulnerabilitySerializer(read_only=True)
    vulnerability_id = serializers.IntegerField(write_only=True, required=False)
    
    class Meta:
        model = RiskScore
        fields = ['id', 'vulnerability', 'vulnerability_id', 'overall_score', 'exploitability_score',
                  'impact_score', 'business_impact_score', 'ai_model_version', 'confidence',
                  'predicted_exploit_likelihood', 'remediation_priority',
                  'factors', 'generated_at', 'updated_at']
        read_only_fields = ['generated_at', 'updated_at']


class RiskAssessmentSerializer(serializers.ModelSerializer):
    """Serializer for RiskAssessment"""
    scan_target_name = serializers.SerializerMethodField()
    
    class Meta:
        model = RiskAssessment
        fields = ['id', 'scan', 'target', 'scan_target_name', 'overall_risk', 'risk_score',
                  'vulnerability_count', 'critical_count', 'high_count', 'medium_count',
                  'low_count', 'ai_insights', 'recommendations', 'generated_at', 'generated_by']
        read_only_fields = ['generated_at']
    
    def get_scan_target_name(self, obj):
        try:
            if obj.scan and hasattr(obj.scan, 'target') and obj.scan.target:
                return obj.scan.target.name
            elif obj.target:
                return obj.target.name
        except Exception:
            pass
        return None


class AIModelSerializer(serializers.ModelSerializer):
    """Serializer for AI Model"""
    class Meta:
        model = AIModel
        fields = ['id', 'name', 'version', 'model_type', 'is_active', 'config',
                  'performance_metrics', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

