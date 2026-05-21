"""
Role-based permission classes for Django REST Framework
"""
from rest_framework import permissions


class IsSecurityAnalyst(permissions.BasePermission):
    """Permission class for Security Analyst role"""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_security_analyst()
        )


class IsComplianceOfficer(permissions.BasePermission):
    """Permission class for Compliance Officer role"""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_compliance_officer()
        )


class IsSOCManager(permissions.BasePermission):
    """Permission class for SOC Manager role"""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_soc_manager()
        )


class IsSecurityAnalystOrSOCManager(permissions.BasePermission):
    """Permission class for Security Analyst or SOC Manager roles"""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            (request.user.is_security_analyst() or request.user.is_soc_manager())
        )


class IsComplianceOfficerOrSOCManager(permissions.BasePermission):
    """Permission class for Compliance Officer or SOC Manager roles"""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            (request.user.is_compliance_officer() or request.user.is_soc_manager())
        )


class IsSOCManagerOrReadOnly(permissions.BasePermission):
    """Permission class: SOC Manager can do everything, others read-only"""
    
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_soc_manager()
        )


class HasRole(permissions.BasePermission):
    """Permission class that checks for specific role(s)"""
    
    def __init__(self, allowed_roles):
        self.allowed_roles = allowed_roles
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_role(*self.allowed_roles)
        )

