"""
Isolation Forest implementation for anomaly detection
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class AnomalyDetectionModel:
    """Isolation Forest model for detecting anomalies"""
    
    def __init__(self, model_path=None, contamination=0.1, n_estimators=100, random_state=42):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = model_path
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.feature_names = []
    
    def extract_vulnerability_features(self, vulnerability, cve_data=None):
        """
        Extract features from vulnerability for anomaly detection
        
        Features for zero-day and unknown threat detection:
        - No CVE ID
        - Unusual severity/CVSS combination
        - Unusual vulnerability type
        - Detection frequency anomalies
        - Pattern deviations
        """
        features = []
        
        # CVE presence (1 if has CVE, 0 if not - anomaly if 0)
        has_cve = 1.0 if (vulnerability.cve_id or (cve_data and cve_data.get('cve_id'))) else 0.0
        features.append(has_cve)
        
        # Severity encoding
        severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        severity = severity_map.get(vulnerability.severity.lower(), 0)
        features.append(severity)
        
        # CVSS score (normalized 0-1)
        cvss_score = vulnerability.cvss_score or 0.0
        if cve_data:
            cvss_score = max(
                cve_data.get('cvss_v3_score', 0) or 0,
                cve_data.get('cvss_v31_score', 0) or 0,
                cve_data.get('cvss_v2_score', 0) or 0,
                cvss_score
            )
        features.append(cvss_score / 10.0)  # Normalize to 0-1
        
        # Detection count (normalized)
        detection_count = vulnerability.detection_count or 1
        features.append(min(detection_count / 100.0, 1.0))  # Normalize
        
        # Age of vulnerability (days since first detected)
        from django.utils import timezone
        days_old = (timezone.now() - vulnerability.first_detected).days
        features.append(days_old / 365.0)  # Normalize to years
        
        # False positive flag (inverse)
        features.append(0.0 if vulnerability.is_false_positive else 1.0)
        
        # Vulnerability type encoding (hash of type string)
        vuln_type = vulnerability.vulnerability_type or 'unknown'
        type_hash = hash(vuln_type) % 1000 / 1000.0  # Normalize hash
        features.append(type_hash)
        
        # Evidence complexity (number of evidence fields)
        evidence = vulnerability.evidence or {}
        evidence_complexity = len(str(evidence)) / 1000.0  # Normalize
        features.append(min(evidence_complexity, 1.0))
        
        # CVE age if available
        if cve_data and cve_data.get('published_date'):
            from django.utils import timezone
            try:
                pub_date = cve_data['published_date']
                if hasattr(pub_date, 'replace'):
                    cve_age = (timezone.now() - pub_date).days / 365.0
                else:
                    cve_age = 0.0
            except:
                cve_age = 0.0
        else:
            cve_age = 0.0
        features.append(cve_age)
        
        # Exploit availability
        exploit_available = 0.0
        if cve_data:
            exploit_available = 1.0 if cve_data.get('exploit_available', False) else 0.0
        features.append(exploit_available)
        
        # Patch availability
        patch_available = 0.0
        if cve_data:
            patch_available = 1.0 if cve_data.get('patch_available', False) else 0.0
        features.append(patch_available)
        
        return np.array(features)
    
    def extract_system_behavior_features(self, scan_data):
        """
        Extract features for system behavior anomaly detection
        
        Features:
        - Scan duration anomalies
        - Vulnerability count anomalies
        - Severity distribution anomalies
        - Scan frequency anomalies
        """
        features = []
        
        # Scan duration (normalized)
        duration = scan_data.get('scan_duration', 0) or 0
        features.append(min(duration / 3600.0, 1.0))  # Normalize to hours
        
        # Total vulnerabilities
        total_vulns = scan_data.get('total_vulnerabilities', 0)
        features.append(min(total_vulns / 1000.0, 1.0))  # Normalize
        
        # Severity distribution
        critical_ratio = scan_data.get('critical_count', 0) / max(total_vulns, 1)
        high_ratio = scan_data.get('high_count', 0) / max(total_vulns, 1)
        medium_ratio = scan_data.get('medium_count', 0) / max(total_vulns, 1)
        
        features.extend([critical_ratio, high_ratio, medium_ratio])
        
        # Scan type encoding
        scan_type = scan_data.get('scan_type', 'unknown')
        type_hash = hash(scan_type) % 1000 / 1000.0
        features.append(type_hash)
        
        # Success rate (if historical data available)
        features.append(1.0)  # Placeholder - would need historical data
        
        return np.array(features)
    
    def extract_configuration_features(self, baseline_config, current_config):
        """
        Extract features for configuration drift detection
        
        Features:
        - Configuration differences
        - Missing configurations
        - New configurations
        - Value changes
        """
        features = []
        
        # Number of config keys
        baseline_keys = set(baseline_config.keys()) if baseline_config else set()
        current_keys = set(current_config.keys()) if current_config else set()
        
        # Missing keys (drift indicator)
        missing_keys = len(baseline_keys - current_keys)
        features.append(min(missing_keys / 100.0, 1.0))
        
        # New keys (drift indicator)
        new_keys = len(current_keys - baseline_keys)
        features.append(min(new_keys / 100.0, 1.0))
        
        # Changed values
        common_keys = baseline_keys & current_keys
        changed_values = sum(
            1 for key in common_keys
            if baseline_config.get(key) != current_config.get(key)
        )
        features.append(min(changed_values / 100.0, 1.0))
        
        # Configuration complexity
        baseline_complexity = len(str(baseline_config)) / 10000.0
        current_complexity = len(str(current_config)) / 10000.0
        features.extend([
            min(baseline_complexity, 1.0),
            min(current_complexity, 1.0)
        ])
        
        return np.array(features)
    
    def extract_network_features(self, network_trace):
        """
        Extract features for network behavior anomaly detection
        
        Expected keys in network_trace:
        - bytes_sent, bytes_received
        - connections, failed_connections
        - avg_latency_ms
        - unique_ips
        - protocol_distribution (dict of protocol -> count)
        - port_distribution (dict of port -> count)
        """
        features = []
        nt = network_trace or {}
        
        bytes_sent = float(nt.get('bytes_sent', 0) or 0)
        bytes_recv = float(nt.get('bytes_received', 0) or 0)
        connections = int(nt.get('connections', 0) or 0)
        failed = int(nt.get('failed_connections', 0) or 0)
        latency = float(nt.get('avg_latency_ms', 0) or 0)
        unique_ips = int(nt.get('unique_ips', 0) or 0)
        
        total_bytes = max(bytes_sent + bytes_recv, 1.0)
        features.extend([
            min(bytes_sent / 1e9, 1.0),          # normalize by 1GB
            min(bytes_recv / 1e9, 1.0),
            min(connections / 10000.0, 1.0),
            min(failed / max(connections, 1), 1.0),  # failure ratio
            min(latency / 1000.0, 1.0),          # normalize to seconds
            min(unique_ips / 10000.0, 1.0)
        ])
        
        proto_dist = nt.get('protocol_distribution', {}) or {}
        port_dist = nt.get('port_distribution', {}) or {}
        
        # Entropy-like measure of distributions
        def distribution_entropy(d):
            total = sum(d.values()) or 1.0
            probs = [v / total for v in d.values() if v > 0]
            import math
            return -sum(p * math.log(p + 1e-12) for p in probs)
        
        proto_entropy = distribution_entropy(proto_dist)
        port_entropy = distribution_entropy(port_dist)
        
        features.extend([
            min(proto_entropy / 5.0, 1.0),
            min(port_entropy / 7.0, 1.0)
        ])
        
        return np.array(features)
    
    def extract_log_features(self, logs_summary):
        """
        Extract features for system logs anomaly detection
        
        Expected keys in logs_summary:
        - total_entries
        - error_count, warning_count, info_count
        - auth_failures
        - suspicious_events
        - avg_events_per_minute
        - keyword_counts (dict of keyword -> count)
        """
        features = []
        ls = logs_summary or {}
        
        total = int(ls.get('total_entries', 0) or 0)
        errors = int(ls.get('error_count', 0) or 0)
        warnings = int(ls.get('warning_count', 0) or 0)
        infos = int(ls.get('info_count', 0) or 0)
        auth_fail = int(ls.get('auth_failures', 0) or 0)
        susp = int(ls.get('suspicious_events', 0) or 0)
        rate = float(ls.get('avg_events_per_minute', 0) or 0)
        
        error_ratio = errors / max(total, 1)
        warn_ratio = warnings / max(total, 1)
        info_ratio = infos / max(total, 1)
        auth_ratio = auth_fail / max(total, 1)
        susp_ratio = susp / max(total, 1)
        
        features.extend([
            min(total / 100000.0, 1.0),
            min(rate / 1000.0, 1.0),
            min(error_ratio, 1.0),
            min(warn_ratio, 1.0),
            min(info_ratio, 1.0),
            min(auth_ratio, 1.0),
            min(susp_ratio, 1.0)
        ])
        
        keyword_counts = ls.get('keyword_counts', {}) or {}
        # Use top 5 suspicious keywords frequency normalized
        suspicious_keywords = ['fail', 'denied', 'unauthorized', 'malware', 'exploit']
        for kw in suspicious_keywords:
            features.append(min((keyword_counts.get(kw, 0) or 0) / max(total, 1), 1.0))
        
        return np.array(features)
    
    def prepare_training_data(self, vulnerabilities, cve_data_map=None):
        """
        Prepare training data from vulnerabilities
        
        Args:
            vulnerabilities: QuerySet or list of Vulnerability objects
            cve_data_map: Optional dict mapping vulnerability IDs to CVE data
        """
        X = []
        
        for vuln in vulnerabilities:
            cve_data = None
            if cve_data_map and vuln.id in cve_data_map:
                cve_data = cve_data_map[vuln.id]
            elif vuln.cve_data:
                cve_data = {
                    'cve_id': vuln.cve_data.cve_id,
                    'cvss_v3_score': vuln.cve_data.cvss_v3_score,
                    'cvss_v31_score': vuln.cve_data.cvss_v31_score,
                    'cvss_v2_score': vuln.cve_data.cvss_v2_score,
                    'published_date': vuln.cve_data.published_date,
                    'exploit_available': vuln.cve_data.exploit_available,
                    'patch_available': vuln.cve_data.patch_available,
                }
            
            features = self.extract_vulnerability_features(vuln, cve_data)
            X.append(features)
        
        return np.array(X)
    
    def train(self, X):
        """
        Train the Isolation Forest model
        
        Args:
            X: Feature matrix
        
        Returns:
            Dictionary with training metrics
        """
        if len(X) < 10:
            raise ValueError("Insufficient training data. Need at least 10 samples.")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        
        # Calculate metrics
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(X)
        
        metrics = {
            'training_samples': len(X),
            'detected_anomalies': int(n_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'mean_anomaly_score': float(np.mean(anomaly_scores)),
            'std_anomaly_score': float(np.std(anomaly_scores)),
        }
        
        logger.info(f"Isolation Forest trained. Detected {n_anomalies} anomalies ({anomaly_rate:.2%})")
        
        return metrics
    
    def predict(self, features):
        """
        Predict if features represent an anomaly
        
        Args:
            features: Feature vector or array of feature vectors
        
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise ValueError("Model not trained. Train a model first.")
        
        # Ensure 2D array
        features = np.array(features)
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict
        predictions = self.model.predict(features_scaled)
        anomaly_scores = self.model.score_samples(features_scaled)
        
        # Convert predictions: -1 (anomaly) -> True, 1 (normal) -> False
        is_anomaly = predictions == -1
        
        results = []
        for i in range(len(features)):
            results.append({
                'is_anomaly': bool(is_anomaly[i]),
                'anomaly_score': float(anomaly_scores[i]),
                'prediction': int(predictions[i]),
            })
        
        return results[0] if len(results) == 1 else results
    
    def save_model(self, path=None):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save. Train a model first.")
        
        save_path = path or self.model_path
        if save_path:
            model_dir = os.path.dirname(save_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir, exist_ok=True)
            
            # Save model and scaler
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler,
                'contamination': self.contamination,
            }, save_path)
            logger.info(f"Model saved to {save_path}")
    
    def load_model(self, path=None):
        """Load a trained model"""
        load_path = path or self.model_path
        
        if not load_path or not os.path.exists(load_path):
            logger.warning(f"Model file not found: {load_path}")
            return False
        
        try:
            data = joblib.load(load_path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.contamination = data.get('contamination', self.contamination)
            logger.info(f"Model loaded from {load_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False

