"""
URLs for scanning module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanTargetViewSet, ScanViewSet, VulnerabilityViewSet

router = DefaultRouter()
router.register(r'targets', ScanTargetViewSet, basename='scantarget')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')

urlpatterns = [
    path('', include(router.urls)),
]

