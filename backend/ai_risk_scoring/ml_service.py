"""
Service layer for ML model operations
"""
from .ml_model import RiskScoringModel
from .models import AIModel, RiskScore
from scanning.models import Vulnerability
from scanning.cve_models import CVEData
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


class MLRiskScoringService:
    """Service for ML-based risk scoring"""
    
    def __init__(self):
        self.model = RiskScoringModel()
        self.model_loaded = False
    
    def load_active_model(self):
        """Load the active AI model"""
        try:
            active_model = AIModel.objects.filter(
                model_type='risk_scoring',
                is_active=True
            ).order_by('-created_at').first()
            
            if active_model:
                model_path = active_model.config.get('model_path')
                if model_path:
                    self.model_loaded = self.model.load_model(model_path)
                else:
                    self.model_loaded = self.model.load_model()
            else:
                self.model_loaded = self.model.load_model()
            
            return self.model_loaded
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
    
    def calculate_risk_score(self, vulnerability):
        """
        Calculate risk score for a vulnerability using ML model
        
        Args:
            vulnerability: Vulnerability instance
        
        Returns:
            RiskScore instance
        """
        if not self.model_loaded:
            self.load_active_model()
        
        if not self.model_loaded or self.model.model is None:
            logger.warning("ML model not available, using fallback calculation")
            return self._fallback_calculation(vulnerability)
        
        # Ensure CVE data is linked if available
        try:
            if vulnerability.cve_id and not vulnerability.cve_data:
                vulnerability.link_cve_data()
        except Exception:
            pass
        
        # Get CVE data
        cve_data = {}
        if vulnerability.cve_data:
            cve = vulnerability.cve_data
            cve_data = {
                'severity': cve.severity,
                'cvss_v3_score': cve.cvss_v3_score,
                'cvss_v31_score': cve.cvss_v31_score,
                'cvss_v2_score': cve.cvss_v2_score,
                'cvss_v3_vector': cve.cvss_v3_vector,
                'cvss_v31_vector': cve.cvss_v31_vector,
                'exploit_available': cve.exploit_available,
                'patch_available': cve.patch_available,
                'published_date': cve.published_date,
            }
        elif vulnerability.cve_id:
            # Try to get CVE data
            cve = CVEData.objects.filter(cve_id=vulnerability.cve_id).first()
            if cve:
                cve_data = {
                    'severity': cve.severity,
                    'cvss_v3_score': cve.cvss_v3_score,
                    'cvss_v31_score': cve.cvss_v31_score,
                    'cvss_v2_score': cve.cvss_v2_score,
                    'cvss_v3_vector': cve.cvss_v3_vector,
                    'cvss_v31_vector': cve.cvss_v31_vector,
                    'exploit_available': cve.exploit_available,
                    'patch_available': cve.patch_available,
                    'published_date': cve.published_date,
                }
        
        # If no CVE data, use vulnerability data only
        if not cve_data:
            cve_data = {
                'severity': vulnerability.severity,
                'cvss_v3_score': vulnerability.cvss_score or 0.0,
                'cvss_v3_vector': vulnerability.cvss_vector or '',
                'exploit_available': False,
                'patch_available': False,
            }
        
        vulnerability_data = {
            'detection_count': vulnerability.detection_count,
            'is_false_positive': vulnerability.is_false_positive,
        }
        
        # Predict with confidence
        prediction = self.model.predict_with_confidence(cve_data, vulnerability_data)
        
        # Calculate exploitability and impact scores
        exploitability_score = self.model._extract_exploitability_from_vector(
            cve_data.get('cvss_v3_vector') or cve_data.get('cvss_v31_vector', ''),
            cve_data.get('cvss_v3_score') or cve_data.get('cvss_v31_score') or cve_data.get('cvss_v2_score', 0.0)
        )
        
        impact_score = self.model._extract_impact_from_vector(
            cve_data.get('cvss_v3_vector') or cve_data.get('cvss_v31_vector', ''),
            cve_data.get('cvss_v3_score') or cve_data.get('cvss_v31_score') or cve_data.get('cvss_v2_score', 0.0)
        )
        
        # Get feature importance for factors
        feature_importance = self.model.get_feature_importance()
        
        severity_str = cve_data.get('severity') or vulnerability.severity or ''
        severity_weight = 1.0
        if severity_str == 'critical':
            severity_weight = 1.2
        elif severity_str == 'high':
            severity_weight = 1.0
        elif severity_str == 'medium':
            severity_weight = 0.8
        elif severity_str == 'low':
            severity_weight = 0.6
        elif severity_str == 'info':
            severity_weight = 0.4
        
        exploit_likelihood = max(min(exploitability_score / 100.0, 1.0), 0.0)
        if cve_data.get('exploit_available'):
            exploit_likelihood = min(exploit_likelihood + 0.1, 1.0)
        if cve_data.get('patch_available'):
            exploit_likelihood = max(exploit_likelihood - 0.05, 0.0)
        
        # Create or update risk score
        risk_score, created = RiskScore.objects.update_or_create(
            vulnerability=vulnerability,
            defaults={
                'overall_score': prediction['score'],
                'exploitability_score': exploitability_score,
                'impact_score': impact_score,
                'confidence': prediction['confidence'],
                'factors': {
                    'prediction_std_dev': prediction['std_dev'],
                    'min_score': prediction['min_score'],
                    'max_score': prediction['max_score'],
                    'feature_importance': feature_importance,
                },
                'ai_analysis': {
                    'model_version': self._get_active_model_version(),
                    'prediction_method': 'random_forest',
                },
                'predicted_exploit_likelihood': exploit_likelihood,
                'remediation_priority': min(int(prediction['score'] * severity_weight), 100),
            }
        )
        
        return risk_score
    
    def _fallback_calculation(self, vulnerability):
        """Fallback risk score calculation when ML model is not available"""
        # Simple calculation based on CVSS score
        cvss_score = 0.0
        if vulnerability.cve_data:
            cvss_score = (
                vulnerability.cve_data.cvss_v3_score or
                vulnerability.cve_data.cvss_v31_score or
                vulnerability.cve_data.cvss_v2_score or 0.0
            )
        elif vulnerability.cvss_score:
            cvss_score = vulnerability.cvss_score
        
        overall_score = cvss_score * 10.0
        
        # Adjust for exploit availability
        if vulnerability.cve_data and vulnerability.cve_data.exploit_available:
            overall_score = min(overall_score * 1.2, 100.0)
        
        risk_score, created = RiskScore.objects.update_or_create(
            vulnerability=vulnerability,
            defaults={
                'overall_score': overall_score,
                'exploitability_score': overall_score * 0.6,
                'impact_score': overall_score * 0.4,
                'confidence': 0.5,  # Lower confidence for fallback
                'factors': {'calculation_method': 'fallback'},
                'ai_analysis': {'model_version': 'fallback', 'prediction_method': 'simple'},
            }
        )
        
        return risk_score
    
    def _get_active_model_version(self):
        """Get version of active model"""
        active_model = AIModel.objects.filter(
            model_type='risk_scoring',
            is_active=True
        ).order_by('-created_at').first()
        
        if active_model:
            return f"{active_model.name} v{active_model.version}"
        return "v1.0"
    
    def train_model(self, vulnerabilities=None, model_name='Risk Scoring Model', model_version='1.0'):
        """
        Train the ML model on vulnerability data
        
        Args:
            vulnerabilities: QuerySet of vulnerabilities (if None, uses all with CVE data)
            model_name: Name for the model
            model_version: Version string
        
        Returns:
            AIModel instance with training metrics
        """
        if vulnerabilities is None:
            vulnerabilities = Vulnerability.objects.filter(
                cve_data__isnull=False
            ).select_related('cve_data', 'risk_score')
        
        # Prepare training data
        X, y = self.model.prepare_training_data(vulnerabilities)
        
        if len(X) < 10:
            raise ValueError("Insufficient training data. Need at least 10 samples with CVE data.")
        
        # Train model
        metrics = self.model.train(X, y)
        
        # Save model
        import os
        from django.conf import settings
        model_dir = os.path.join(settings.BASE_DIR, 'ai_risk_scoring', 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_filename = f"risk_scoring_model_{model_version.replace('.', '_')}.pkl"
        model_path = os.path.join(model_dir, model_filename)
        
        self.model.save_model(model_path)
        
        # Deactivate old models
        AIModel.objects.filter(model_type='risk_scoring', is_active=True).update(is_active=False)
        
        # Create new model record
        ai_model = AIModel.objects.create(
            name=model_name,
            version=model_version,
            model_type='risk_scoring',
            is_active=True,
            config={
                'model_path': model_path,
                'n_estimators': 100,
                'max_depth': 20,
            },
            performance_metrics=metrics,
        )
        
        logger.info(f"Model trained and saved: {ai_model.name} v{ai_model.version}")
        
        return ai_model

