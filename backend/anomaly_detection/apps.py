from django.apps import AppConfig


class AnomalyDetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'anomaly_detection'
    
    def ready(self):
        """Import signals when app is ready"""
        import anomaly_detection.signals  # noqa

