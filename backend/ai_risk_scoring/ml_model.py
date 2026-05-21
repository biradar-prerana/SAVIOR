"""
Random Forest ML model for AI risk scoring
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import joblib
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class RiskScoringModel:
    """Random Forest model for predicting risk scores (0-100)"""
    
    def __init__(self, model_path=None):
        self.model = None
        self.label_encoders = {}
        self.model_path = model_path or os.path.join(
            settings.BASE_DIR, 'ai_risk_scoring', 'models', 'risk_scoring_model.pkl'
        )
        self.ensure_model_dir()
    
    def ensure_model_dir(self):
        """Ensure model directory exists"""
        model_dir = os.path.dirname(self.model_path)
        if not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)
    
    def extract_features(self, cve_data, vulnerability_data=None):
        """
        Extract features from CVE data and vulnerability data
        
        Features:
        - Severity (encoded)
        - Exploitability metrics (from CVSS)
        - Impact metrics (from CVSS)
        - CVE metadata
        
        Returns:
            numpy array of features
        """
        features = []
        
        # Severity encoding
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0,
            'none': 0
        }
        severity = cve_data.get('severity', 'low')
        features.append(severity_map.get(severity.lower(), 0))
        
        # CVSS v3 scores (preferred)
        cvss_v3_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v31_score') or 0.0
        cvss_v2_score = cve_data.get('cvss_v2_score') or 0.0
        
        # Use highest CVSS score
        base_score = max(cvss_v3_score, cvss_v2_score)
        features.append(base_score)
        
        # Exploitability metrics from CVSS vector
        cvss_vector = cve_data.get('cvss_v3_vector') or cve_data.get('cvss_v31_vector') or ''
        exploitability_score = self._extract_exploitability_from_vector(cvss_vector, base_score)
        features.append(exploitability_score)
        
        # Impact metrics from CVSS vector
        impact_score = self._extract_impact_from_vector(cvss_vector, base_score)
        features.append(impact_score)
        
        # Exploit availability (binary)
        features.append(1.0 if cve_data.get('exploit_available', False) else 0.0)
        
        # Patch availability (binary)
        features.append(1.0 if cve_data.get('patch_available', False) else 0.0)
        
        # Age of CVE (days since published)
        if cve_data.get('published_date'):
            from django.utils import timezone
            from datetime import datetime
            try:
                if isinstance(cve_data['published_date'], str):
                    pub_date = datetime.fromisoformat(cve_data['published_date'].replace('Z', '+00:00'))
                else:
                    pub_date = cve_data['published_date']
                days_old = (timezone.now() - pub_date).days if hasattr(pub_date, 'replace') else 0
            except:
                days_old = 0
        else:
            days_old = 0
        features.append(days_old / 365.0)  # Normalize to years
        
        # Additional vulnerability context if available
        if vulnerability_data:
            # Detection count (how many times seen)
            detection_count = vulnerability_data.get('detection_count', 1)
            features.append(min(detection_count / 10.0, 1.0))  # Normalize to 0-1
            
            # False positive flag (inverse)
            is_false_positive = vulnerability_data.get('is_false_positive', False)
            features.append(0.0 if is_false_positive else 1.0)
        else:
            features.append(0.0)  # Default detection count
            features.append(1.0)  # Default not false positive
        
        return np.array(features)
    
    def _extract_exploitability_from_vector(self, cvss_vector, base_score):
        """
        Extract exploitability score from CVSS vector
        If vector not available, estimate from base score
        """
        if not cvss_vector:
            # Estimate exploitability as 60% of base score if no vector
            return base_score * 0.6
        
        # Parse CVSS vector for exploitability metrics
        # Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        exploitability_factors = {
            'AV:N': 0.85,  # Network
            'AV:A': 0.62,  # Adjacent
            'AV:L': 0.55,  # Local
            'AV:P': 0.20,  # Physical
            
            'AC:L': 0.77,  # Low
            'AC:H': 0.44,  # High
            
            'PR:N': 0.85,  # None
            'PR:L': 0.62,  # Low
            'PR:H': 0.27,  # High
            
            'UI:N': 0.85,  # None
            'UI:R': 0.62,  # Required
            
            'S:U': 1.0,    # Unchanged
            'S:C': 1.0,    # Changed
        }
        
        exploitability = 8.22
        for factor, value in exploitability_factors.items():
            if factor in cvss_vector:
                exploitability *= value
        
        # Normalize to 0-10 scale, then convert to 0-100
        return min(exploitability, 10.0) * 10.0
    
    def _extract_impact_from_vector(self, cvss_vector, base_score):
        """
        Extract impact score from CVSS vector
        If vector not available, estimate from base score
        """
        if not cvss_vector:
            # Estimate impact as 40% of base score if no vector
            return base_score * 0.4
        
        # Parse CVSS vector for impact metrics
        impact_factors = {
            'C:H': 0.56,  # High Confidentiality
            'C:L': 0.22,  # Low Confidentiality
            'C:N': 0.0,   # None
            
            'I:H': 0.56,  # High Integrity
            'I:L': 0.22,  # Low Integrity
            'I:N': 0.0,   # None
            
            'A:H': 0.56,  # High Availability
            'A:L': 0.22,  # Low Availability
            'A:N': 0.0,   # None
        }
        
        impact = 0.0
        for factor, value in impact_factors.items():
            if factor in cvss_vector:
                impact += value
        
        # Calculate impact score (ISC)
        isc_base = 1 - ((1 - impact) * (1 - impact) * (1 - impact))
        isc_modified = isc_base  # Simplified, assuming no scope change
        
        # Normalize to 0-10 scale, then convert to 0-100
        return min(isc_modified * 10.0, 10.0) * 10.0
    
    def prepare_training_data(self, vulnerabilities):
        """
        Prepare training data from vulnerabilities with CVE data
        
        Args:
            vulnerabilities: QuerySet or list of Vulnerability objects with CVE data
        
        Returns:
            X (features), y (target risk scores)
        """
        X = []
        y = []
        
        for vuln in vulnerabilities:
            if not vuln.cve_data:
                continue
            
            cve = vuln.cve_data
            
            # Extract features
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
            
            vulnerability_data = {
                'detection_count': vuln.detection_count,
                'is_false_positive': vuln.is_false_positive,
            }
            
            features = self.extract_features(cve_data, vulnerability_data)
            X.append(features)
            
            # Calculate target risk score (0-100)
            # Use existing risk score if available, otherwise calculate from CVSS
            if hasattr(vuln, 'risk_score') and vuln.risk_score:
                target_score = vuln.risk_score.overall_score
            else:
                # Calculate from CVSS score (scale 0-10 to 0-100)
                cvss_score = cve.cvss_v3_score or cve.cvss_v31_score or cve.cvss_v2_score or 0.0
                target_score = cvss_score * 10.0
                
                # Adjust based on exploit availability
                if cve.exploit_available:
                    target_score = min(target_score * 1.2, 100.0)
            
            y.append(target_score)
        
        return np.array(X), np.array(y)
    
    def train(self, X, y, test_size=0.2, random_state=42, n_estimators=100, max_depth=20):
        """
        Train the Random Forest model
        
        Args:
            X: Feature matrix
            y: Target values (risk scores 0-100)
            test_size: Proportion of data for testing
            random_state: Random seed
            n_estimators: Number of trees in forest
            max_depth: Maximum depth of trees
        
        Returns:
            Dictionary with training metrics
        """
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )
        
        # Train model
        self.model = RandomForestRegressor(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            min_samples_split=2,
            min_samples_leaf=1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_train_pred = self.model.predict(X_train)
        y_test_pred = self.model.predict(X_test)
        
        metrics = {
            'train_mse': mean_squared_error(y_train, y_train_pred),
            'train_mae': mean_absolute_error(y_train, y_train_pred),
            'train_r2': r2_score(y_train, y_train_pred),
            'test_mse': mean_squared_error(y_test, y_test_pred),
            'test_mae': mean_absolute_error(y_test, y_test_pred),
            'test_r2': r2_score(y_test, y_test_pred),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
        }
        
        logger.info(f"Model trained. Test R²: {metrics['test_r2']:.4f}, Test MAE: {metrics['test_mae']:.2f}")
        
        return metrics
    
    def predict(self, cve_data, vulnerability_data=None):
        """
        Predict risk score for a vulnerability
        
        Args:
            cve_data: Dictionary with CVE information
            vulnerability_data: Optional dictionary with vulnerability context
        
        Returns:
            Risk score (0-100)
        """
        if self.model is None:
            self.load_model()
        
        if self.model is None:
            raise ValueError("Model not loaded. Train or load a model first.")
        
        features = self.extract_features(cve_data, vulnerability_data)
        features = features.reshape(1, -1)
        
        score = self.model.predict(features)[0]
        
        # Ensure score is in 0-100 range
        score = max(0.0, min(100.0, score))
        
        return float(score)
    
    def predict_with_confidence(self, cve_data, vulnerability_data=None):
        """
        Predict risk score with confidence interval
        
        Returns:
            Dictionary with score, confidence (std dev), and min/max
        """
        if self.model is None:
            self.load_model()
        
        if self.model is None:
            raise ValueError("Model not loaded. Train or load a model first.")
        
        features = self.extract_features(cve_data, vulnerability_data)
        features = features.reshape(1, -1)
        
        # Get predictions from all trees
        predictions = [tree.predict(features)[0] for tree in self.model.estimators_]
        
        score = np.mean(predictions)
        std_dev = np.std(predictions)
        confidence = 1.0 - min(std_dev / 50.0, 1.0)  # Normalize to 0-1
        
        return {
            'score': float(max(0.0, min(100.0, score))),
            'confidence': float(confidence),
            'std_dev': float(std_dev),
            'min_score': float(max(0.0, min(100.0, score - std_dev))),
            'max_score': float(min(100.0, max(0.0, score + std_dev))),
        }
    
    def save_model(self, path=None):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save. Train a model first.")
        
        save_path = path or self.model_path
        self.ensure_model_dir()
        
        joblib.dump(self.model, save_path)
        logger.info(f"Model saved to {save_path}")
    
    def load_model(self, path=None):
        """Load a trained model"""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            logger.warning(f"Model file not found: {load_path}")
            return False
        
        try:
            self.model = joblib.load(load_path)
            logger.info(f"Model loaded from {load_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
    
    def get_feature_importance(self):
        """Get feature importance from the model"""
        if self.model is None:
            return None
        
        feature_names = [
            'severity',
            'base_cvss_score',
            'exploitability_score',
            'impact_score',
            'exploit_available',
            'patch_available',
            'cve_age_years',
            'detection_count',
            'not_false_positive',
        ]
        
        importances = self.model.feature_importances_
        return dict(zip(feature_names, importances))

