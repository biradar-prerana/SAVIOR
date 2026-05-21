"""
Serializers for anomaly detection module
"""
from rest_framework import serializers
from .models import AnomalyDetection, AnomalyModel, AnomalyBaseline
from scanning.serializers import VulnerabilitySerializer, ScanSerializer, ScanTargetSerializer


class AnomalyDetectionSerializer(serializers.ModelSerializer):
    """Serializer for AnomalyDetection"""
    vulnerability_data = VulnerabilitySerializer(source='vulnerability', read_only=True)
    scan_data = ScanSerializer(source='scan', read_only=True)
    target_data = ScanTargetSerializer(source='target', read_only=True)
    detected_by_username = serializers.CharField(source='detected_by.username', read_only=True)
    investigated_by_username = serializers.CharField(source='investigated_by.username', read_only=True)
    
    class Meta:
        model = AnomalyDetection
        fields = [
            'id', 'anomaly_type', 'severity', 'status', 'vulnerability', 'vulnerability_data',
            'scan', 'scan_data', 'target', 'target_data', 'title', 'description',
            'anomaly_score', 'confidence', 'feature_vector', 'anomaly_factors',
            'is_potential_zero_day', 'has_no_cve', 'unusual_pattern',
            'baseline_config', 'current_config', 'drift_details',
            'detected_at', 'detected_by', 'detected_by_username', 'model_version',
            'investigated_by', 'investigated_by_username', 'investigation_notes',
            'resolved_at'
        ]
        read_only_fields = ['detected_at', 'detected_by']


class AnomalyModelSerializer(serializers.ModelSerializer):
    """Serializer for AnomalyModel"""
    class Meta:
        model = AnomalyModel
        fields = [
            'id', 'name', 'version', 'model_type', 'is_active', 'config',
            'performance_metrics', 'model_file_path', 'training_samples',
            'contamination', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class AnomalyBaselineSerializer(serializers.ModelSerializer):
    """Serializer for AnomalyBaseline"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    target_data = ScanTargetSerializer(source='target', read_only=True)
    
    class Meta:
        model = AnomalyBaseline
        fields = [
            'id', 'name', 'baseline_type', 'target', 'target_data',
            'baseline_data', 'feature_weights', 'created_by', 'created_by_username',
            'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['created_by', 'created_at', 'updated_at']

