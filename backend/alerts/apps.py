from django.apps import AppConfig


class AlertsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'alerts'
    
    def ready(self):
        """Import signals when app is ready"""
        import alerts.signals  # noqa

