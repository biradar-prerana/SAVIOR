# Authentication Module

This module provides role-based authentication for the SAVIOR platform.

## Roles

1. **Security Analyst** (`security_analyst`)
   - Can perform vulnerability scans
   - Can view and manage scan results
   - Can generate reports

2. **Compliance Officer** (`compliance_officer`)
   - Can view compliance reports
   - Can manage report templates
   - Can schedule reports

3. **SOC Manager** (`soc_manager`)
   - Full access to all features
   - Can manage users
   - Can configure integrations
   - Can view all scans and reports

## API Endpoints

- `POST /api/auth/register/` - Register a new user
- `POST /api/auth/login/` - Login and get authentication token
- `POST /api/auth/logout/` - Logout and invalidate token
- `GET /api/auth/profile/` - Get current user profile
- `PUT /api/auth/profile/update/` - Update user profile
- `POST /api/auth/change-password/` - Change password
- `GET /api/auth/users/` - List users (SOC Manager only)

## Usage in Views

```python
from authentication.permissions import IsSecurityAnalyst, IsSOCManager

class MyViewSet(viewsets.ModelViewSet):
    permission_classes = [IsSecurityAnalyst]  # Only Security Analysts can access
```

## Creating Default Users

Run the management command to create default users:

```bash
python manage.py create_roles
```

This creates:
- Security Analyst: `analyst` / `analyst123`
- Compliance Officer: `compliance` / `compliance123`
- SOC Manager: `soc_manager` / `soc123`

## Permission Classes

- `IsSecurityAnalyst` - Only Security Analysts
- `IsComplianceOfficer` - Only Compliance Officers
- `IsSOCManager` - Only SOC Managers
- `IsSecurityAnalystOrSOCManager` - Security Analysts or SOC Managers
- `IsComplianceOfficerOrSOCManager` - Compliance Officers or SOC Managers
- `IsSOCManagerOrReadOnly` - SOC Managers can do everything, others read-only

