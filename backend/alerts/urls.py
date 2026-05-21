"""
URLs for alerts module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AlertViewSet, AlertRuleViewSet

router = DefaultRouter()
router.register(r'alerts', AlertViewSet, basename='alert')
router.register(r'rules', AlertRuleViewSet, basename='alertrule')

urlpatterns = [
    path('', include(router.urls)),
]

