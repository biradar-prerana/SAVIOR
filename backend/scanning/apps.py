from django.apps import AppConfig


class ScanningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanning'
    
    def ready(self):
        """Import signals when app is ready"""
        import scanning.signals  # noqa

