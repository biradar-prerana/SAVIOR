"""
SAVIOR URL Configuration
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/scanning/', include('scanning.urls')),
    path('api/ai-risk/', include('ai_risk_scoring.urls')),
    path('api/anomaly/', include('anomaly_detection.urls')),
    path('api/reporting/', include('reporting.urls')),
    path('api/integrations/', include('integrations.urls')),
    path('api/alerts/', include('alerts.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

