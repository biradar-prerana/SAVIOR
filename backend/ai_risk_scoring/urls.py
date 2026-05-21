"""
URLs for AI Risk Scoring module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RiskScoreViewSet, RiskAssessmentViewSet, AIModelViewSet

router = DefaultRouter()
router.register(r'scores', RiskScoreViewSet, basename='riskscore')
router.register(r'assessments', RiskAssessmentViewSet, basename='riskassessment')
router.register(r'models', AIModelViewSet, basename='aimodel')

urlpatterns = [
    path('', include(router.urls)),
]

