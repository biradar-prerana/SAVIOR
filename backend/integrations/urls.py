"""
URLs for integrations module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import IntegrationViewSet, IntegrationEventViewSet, WebhookEndpointViewSet

router = DefaultRouter()
router.register(r'integrations', IntegrationViewSet, basename='integration')
router.register(r'events', IntegrationEventViewSet, basename='integrationevent')
router.register(r'webhooks', WebhookEndpointViewSet, basename='webhookendpoint')

urlpatterns = [
    path('', include(router.urls)),
]

