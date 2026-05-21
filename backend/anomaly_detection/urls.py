"""
URLs for anomaly detection module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AnomalyDetectionViewSet, AnomalyModelViewSet, AnomalyBaselineViewSet

router = DefaultRouter()
router.register(r'anomalies', AnomalyDetectionViewSet, basename='anomaly')
router.register(r'models', AnomalyModelViewSet, basename='anomalymodel')
router.register(r'baselines', AnomalyBaselineViewSet, basename='anomalybaseline')

urlpatterns = [
    path('', include(router.urls)),
]

