"""
Tests for authentication module
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


class AuthenticationTestCase(TestCase):
    """Test cases for authentication"""
    
    def setUp(self):
        self.client = APIClient()
        self.analyst = User.objects.create_user(
            username='test_analyst',
            password='testpass123',
            role='security_analyst',
            email='analyst@test.com'
        )
        self.compliance = User.objects.create_user(
            username='test_compliance',
            password='testpass123',
            role='compliance_officer',
            email='compliance@test.com'
        )
        self.soc_manager = User.objects.create_user(
            username='test_soc',
            password='testpass123',
            role='soc_manager',
            email='soc@test.com'
        )
    
    def test_user_creation(self):
        """Test user creation with roles"""
        self.assertEqual(self.analyst.role, 'security_analyst')
        self.assertEqual(self.compliance.role, 'compliance_officer')
        self.assertEqual(self.soc_manager.role, 'soc_manager')
    
    def test_role_methods(self):
        """Test role checking methods"""
        self.assertTrue(self.analyst.is_security_analyst())
        self.assertTrue(self.compliance.is_compliance_officer())
        self.assertTrue(self.soc_manager.is_soc_manager())
    
    def test_user_registration(self):
        """Test user registration endpoint"""
        data = {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'newpass123',
            'password2': 'newpass123',
            'role': 'security_analyst'
        }
        response = self.client.post('/api/auth/register/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
    
    def test_user_login(self):
        """Test user login endpoint"""
        data = {
            'username': 'test_analyst',
            'password': 'testpass123'
        }
        response = self.client.post('/api/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
    
    def test_user_profile(self):
        """Test user profile endpoint"""
        self.client.force_authenticate(user=self.analyst)
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'test_analyst')
        self.assertEqual(response.data['role'], 'security_analyst')

