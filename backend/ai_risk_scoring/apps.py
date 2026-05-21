from django.apps import AppConfig


class AiRiskScoringConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ai_risk_scoring'
    
    def ready(self):
        import ai_risk_scoring.signals  # noqa

