"""
URLs for authentication module
"""
from django.urls import path
from .views import (
    register, login_view, logout_view, user_profile,
    update_profile, change_password, UserListView
)

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', user_profile, name='user-profile'),
    path('profile/update/', update_profile, name='update-profile'),
    path('change-password/', change_password, name='change-password'),
    path('users/', UserListView.as_view(), name='user-list'),
]

