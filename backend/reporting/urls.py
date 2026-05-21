"""
URLs for reporting module
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ReportViewSet, ReportTemplateViewSet, ReportScheduleViewSet

router = DefaultRouter()
router.register(r'reports', ReportViewSet, basename='report')
router.register(r'templates', ReportTemplateViewSet, basename='reporttemplate')
router.register(r'schedules', ReportScheduleViewSet, basename='reportschedule')

urlpatterns = [
    path('', include(router.urls)),
]

