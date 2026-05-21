"""
Custom User model with role-based access control
"""
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom User model with role field"""
    
    ROLE_CHOICES = [
        ('security_analyst', 'Security Analyst'),
        ('compliance_officer', 'Compliance Officer'),
        ('soc_manager', 'SOC Manager'),
    ]
    
    role = models.CharField(
        max_length=50,
        choices=ROLE_CHOICES,
        default='security_analyst',
        help_text='User role for access control'
    )
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-date_joined']
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def is_security_analyst(self):
        """Check if user is a Security Analyst"""
        return self.role == 'security_analyst'
    
    def is_compliance_officer(self):
        """Check if user is a Compliance Officer"""
        return self.role == 'compliance_officer'
    
    def is_soc_manager(self):
        """Check if user is a SOC Manager"""
        return self.role == 'soc_manager'
    
    def has_role(self, *roles):
        """Check if user has any of the specified roles"""
        return self.role in roles

