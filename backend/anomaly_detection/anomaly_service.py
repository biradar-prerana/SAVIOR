"""
Service layer for anomaly detection operations
"""
from .isolation_forest import AnomalyDetectionModel
from .models import AnomalyDetection, AnomalyModel, AnomalyBaseline
from scanning.models import Vulnerability, Scan, ScanTarget
from scanning.cve_models import CVEData
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """Service for detecting anomalies using Isolation Forest"""
    
    def __init__(self):
        self.model = None
        self.model_loaded = False
    
    def load_active_model(self, model_type='vulnerability'):
        """Load the active anomaly detection model"""
        try:
            active_model = AnomalyModel.objects.filter(
                model_type=model_type,
                is_active=True
            ).order_by('-created_at').first()
            
            if active_model:
                self.model = AnomalyDetectionModel(
                    contamination=active_model.contamination,
                    n_estimators=active_model.config.get('n_estimators', 100),
                )
                if active_model.model_file_path:
                    self.model_loaded = self.model.load_model(active_model.model_file_path)
                else:
                    self.model_loaded = False
            else:
                # Try default model
                self.model = AnomalyDetectionModel()
                self.model_loaded = False
            
            return self.model_loaded
        except Exception as e:
            logger.error(f"Error loading anomaly model: {str(e)}")
            return False
    
    def detect_vulnerability_anomalies(self, vulnerability):
        """
        Detect anomalies in a vulnerability
        
        Returns:
            AnomalyDetection instance if anomaly detected, None otherwise
        """
        if not self.model_loaded:
            self.load_active_model('vulnerability')
        
        if not self.model_loaded or self.model.model is None:
            logger.warning("Anomaly detection model not available")
            return None
        
        # Get CVE data
        cve_data = None
        if vulnerability.cve_data:
            cve = vulnerability.cve_data
            cve_data = {
                'cve_id': cve.cve_id,
                'cvss_v3_score': cve.cvss_v3_score,
                'cvss_v31_score': cve.cvss_v31_score,
                'cvss_v2_score': cve.cvss_v2_score,
                'published_date': cve.published_date,
                'exploit_available': cve.exploit_available,
                'patch_available': cve.patch_available,
            }
        elif vulnerability.cve_id:
            cve = CVEData.objects.filter(cve_id=vulnerability.cve_id).first()
            if cve:
                cve_data = {
                    'cve_id': cve.cve_id,
                    'cvss_v3_score': cve.cvss_v3_score,
                    'cvss_v31_score': cve.cvss_v31_score,
                    'cvss_v2_score': cve.cvss_v2_score,
                    'published_date': cve.published_date,
                    'exploit_available': cve.exploit_available,
                    'patch_available': cve.patch_available,
                }
        
        # Extract features
        features = self.model.extract_vulnerability_features(vulnerability, cve_data)
        
        # Predict
        prediction = self.model.predict(features)
        
        if prediction['is_anomaly']:
            # Determine anomaly type
            anomaly_type = 'unknown_threat'
            is_zero_day = False
            
            # Check for zero-day indicators
            if not vulnerability.cve_id and not cve_data:
                anomaly_type = 'zero_day'
                is_zero_day = True
            
            # Check for unusual patterns
            if vulnerability.cvss_score and vulnerability.cvss_score > 8.0 and vulnerability.severity != 'critical':
                anomaly_type = 'vulnerability_pattern'
            
            # Determine severity based on anomaly score
            anomaly_score = prediction['anomaly_score']
            if anomaly_score < -0.5:
                severity = 'critical'
            elif anomaly_score < -0.3:
                severity = 'high'
            elif anomaly_score < -0.1:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Create anomaly detection record
            anomaly = AnomalyDetection.objects.create(
                anomaly_type=anomaly_type,
                severity=severity,
                vulnerability=vulnerability,
                scan=vulnerability.scan,
                target=vulnerability.scan.target if vulnerability.scan else None,
                title=f"Anomaly detected: {vulnerability.title}",
                description=f"Unusual vulnerability pattern detected. Anomaly score: {anomaly_score:.3f}",
                anomaly_score=anomaly_score,
                confidence=abs(anomaly_score),  # Use absolute value as confidence
                feature_vector={f'feature_{i}': float(f) for i, f in enumerate(features)},
                is_potential_zero_day=is_zero_day,
                has_no_cve=not bool(vulnerability.cve_id or cve_data),
                unusual_pattern=f"CVSS: {vulnerability.cvss_score}, Severity: {vulnerability.severity}, Type: {vulnerability.vulnerability_type}",
                model_version=self._get_active_model_version('vulnerability'),
            )
            
            logger.info(f"Anomaly detected: {anomaly.id} - {anomaly.title}")
            return anomaly
        
        return None
    
    def detect_network_anomalies(self, target, network_trace):
        """Detect anomalies in network behavior"""
        if not self.model_loaded:
            self.load_active_model('system_behavior')
        
        features = None
        prediction = None
        if self.model and self.model.model is not None:
            features = self.model.extract_network_features(network_trace)
            prediction = self.model.predict(features)
        
        # Fallback heuristic if model unavailable
        if not prediction:
            nt = network_trace or {}
            connections = int(nt.get('connections', 0) or 0)
            failed = int(nt.get('failed_connections', 0) or 0)
            fail_ratio = failed / max(connections, 1)
            bytes_sent = float(nt.get('bytes_sent', 0) or 0)
            bytes_recv = float(nt.get('bytes_received', 0) or 0)
            total_bytes = bytes_sent + bytes_recv
            unique_ips = int(nt.get('unique_ips', 0) or 0)
            anomaly_score = -min((fail_ratio * 2.0) + (unique_ips / 10000.0) + (total_bytes / 1e9), 1.0)
            is_anomaly = fail_ratio > 0.2 or unique_ips > 500 or total_bytes > 5e9
        else:
            is_anomaly = prediction['is_anomaly']
            anomaly_score = prediction['anomaly_score']
        
        if is_anomaly:
            severity = 'high' if anomaly_score < -0.3 else 'medium'
            anomaly = AnomalyDetection.objects.create(
                anomaly_type='network_anomaly',
                severity=severity,
                target=target,
                title=f"Network anomaly detected: {target.name}",
                description="Unusual network behavior observed",
                anomaly_score=anomaly_score,
                confidence=abs(anomaly_score),
                feature_vector={f'feature_{i}': float(f) for i, f in enumerate(features)} if features is not None else {},
                model_version=self._get_active_model_version('system_behavior'),
            )
            return anomaly
        return None
    
    def detect_log_anomalies(self, target, logs_summary):
        """Detect anomalies in system logs"""
        if not self.model_loaded:
            self.load_active_model('system_behavior')
        
        features = None
        prediction = None
        if self.model and self.model.model is not None:
            features = self.model.extract_log_features(logs_summary)
            prediction = self.model.predict(features)
        
        # Fallback heuristic
        if not prediction:
            ls = logs_summary or {}
            total = int(ls.get('total_entries', 0) or 0)
            errors = int(ls.get('error_count', 0) or 0)
            auth_fail = int(ls.get('auth_failures', 0) or 0)
            susp = int(ls.get('suspicious_events', 0) or 0)
            error_ratio = errors / max(total, 1)
            anomaly_score = -min(error_ratio * 2.0 + auth_fail / max(total, 1) + susp / max(total, 1), 1.0)
            is_anomaly = error_ratio > 0.3 or auth_fail > 100 or susp > 50
        else:
            is_anomaly = prediction['is_anomaly']
            anomaly_score = prediction['anomaly_score']
        
        if is_anomaly:
            severity = 'high' if anomaly_score < -0.3 else 'medium'
            anomaly = AnomalyDetection.objects.create(
                anomaly_type='log_anomaly',
                severity=severity,
                target=target,
                title=f"System log anomaly detected: {target.name}",
                description="Unusual log activity observed",
                anomaly_score=anomaly_score,
                confidence=abs(anomaly_score),
                feature_vector={f'feature_{i}': float(f) for i, f in enumerate(features)} if features is not None else {},
                model_version=self._get_active_model_version('system_behavior'),
            )
            return anomaly
        return None
    
    def detect_scan_anomalies(self, scan):
        """Detect anomalies in scan results"""
        if not self.model_loaded:
            self.load_active_model('system_behavior')
        
        if not self.model_loaded or self.model.model is None:
            return None
        
        # Extract scan features
        scan_data = {
            'scan_duration': scan.scan_duration,
            'total_vulnerabilities': scan.total_vulnerabilities,
            'critical_count': scan.critical_count,
            'high_count': scan.high_count,
            'medium_count': scan.medium_count,
            'scan_type': scan.scan_type,
        }
        
        features = self.model.extract_system_behavior_features(scan_data)
        prediction = self.model.predict(features)
        
        if prediction['is_anomaly']:
            anomaly_score = prediction['anomaly_score']
            severity = 'high' if anomaly_score < -0.3 else 'medium'
            
            anomaly = AnomalyDetection.objects.create(
                anomaly_type='scan_anomaly',
                severity=severity,
                scan=scan,
                target=scan.target,
                title=f"Anomalous scan detected: {scan.target.name}",
                description=f"Unusual scan pattern detected. Duration: {scan.scan_duration}s, Vulnerabilities: {scan.total_vulnerabilities}",
                anomaly_score=anomaly_score,
                confidence=abs(anomaly_score),
                feature_vector={f'feature_{i}': float(f) for i, f in enumerate(features)},
                model_version=self._get_active_model_version('system_behavior'),
            )
            
            return anomaly
        
        return None
    
    def detect_configuration_drift(self, target, current_config, baseline_name=None):
        """Detect configuration drift"""
        # Get baseline
        if baseline_name:
            baseline = AnomalyBaseline.objects.filter(
                name=baseline_name,
                target=target,
                is_active=True
            ).first()
        else:
            baseline = AnomalyBaseline.objects.filter(
                target=target,
                baseline_type='system_config',
                is_active=True
            ).order_by('-created_at').first()
        
        if not baseline:
            logger.warning(f"No baseline found for target {target.id}")
            return None
        
        # Extract configuration features
        features = self.model.extract_configuration_features(
            baseline.baseline_data,
            current_config
        )
        
        # Simple threshold-based detection (could use ML model)
        missing_keys = len(set(baseline.baseline_data.keys()) - set(current_config.keys()))
        new_keys = len(set(current_config.keys()) - set(baseline.baseline_data.keys()))
        changed_values = sum(
            1 for key in set(baseline.baseline_data.keys()) & set(current_config.keys())
            if baseline.baseline_data.get(key) != current_config.get(key)
        )
        
        if missing_keys > 0 or new_keys > 0 or changed_values > 0:
            drift_score = (missing_keys + new_keys + changed_values) / max(len(baseline.baseline_data), 1)
            severity = 'high' if drift_score > 0.3 else 'medium' if drift_score > 0.1 else 'low'
            
            anomaly = AnomalyDetection.objects.create(
                anomaly_type='configuration_drift',
                severity=severity,
                target=target,
                title=f"Configuration drift detected: {target.name}",
                description=f"Configuration has changed. Missing: {missing_keys}, New: {new_keys}, Changed: {changed_values}",
                anomaly_score=-drift_score,  # Negative indicates anomaly
                confidence=min(drift_score, 1.0),
                baseline_config=baseline.baseline_data,
                current_config=current_config,
                drift_details={
                    'missing_keys': list(set(baseline.baseline_data.keys()) - set(current_config.keys())),
                    'new_keys': list(set(current_config.keys()) - set(baseline.baseline_data.keys())),
                    'changed_keys': [
                        key for key in set(baseline.baseline_data.keys()) & set(current_config.keys())
                        if baseline.baseline_data.get(key) != current_config.get(key)
                    ],
                },
            )
            
            return anomaly
        
        return None
    
    def _get_active_model_version(self, model_type):
        """Get version of active model"""
        active_model = AnomalyModel.objects.filter(
            model_type=model_type,
            is_active=True
        ).order_by('-created_at').first()
        
        if active_model:
            return f"{active_model.name} v{active_model.version}"
        return "v1.0"
    
    def train_model(self, vulnerabilities=None, model_name='Anomaly Detection Model', 
                   model_version='1.0', model_type='vulnerability', contamination=0.1):
        """Train anomaly detection model"""
        from .isolation_forest import AnomalyDetectionModel
        
        if vulnerabilities is None:
            vulnerabilities = Vulnerability.objects.select_related('cve_data')
        
        # Create model
        self.model = AnomalyDetectionModel(contamination=contamination)
        
        # Prepare training data
        X = self.model.prepare_training_data(vulnerabilities)
        
        if len(X) < 10:
            raise ValueError("Insufficient training data. Need at least 10 samples.")
        
        # Train
        metrics = self.model.train(X)
        
        # Save model
        import os
        from django.conf import settings
        model_dir = os.path.join(settings.BASE_DIR, 'anomaly_detection', 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_filename = f"anomaly_model_{model_type}_{model_version.replace('.', '_')}.pkl"
        model_path = os.path.join(model_dir, model_filename)
        
        self.model.save_model(model_path)
        
        # Deactivate old models
        AnomalyModel.objects.filter(model_type=model_type, is_active=True).update(is_active=False)
        
        # Create model record
        anomaly_model = AnomalyModel.objects.create(
            name=model_name,
            version=model_version,
            model_type=model_type,
            is_active=True,
            contamination=contamination,
            config={
                'n_estimators': self.model.n_estimators,
                'random_state': self.model.random_state,
            },
            performance_metrics=metrics,
            model_file_path=model_path,
            training_samples=len(X),
        )
        
        self.model_loaded = True
        
        logger.info(f"Anomaly detection model trained: {anomaly_model.name} v{anomaly_model.version}")
        
        return anomaly_model

