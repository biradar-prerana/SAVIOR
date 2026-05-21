# SAVIOR - AI-Based Vulnerability Scanner

SAVIOR is a comprehensive full-stack vulnerability scanning platform that leverages AI for intelligent risk assessment and reporting.

## 🏗️ Project Structure

```
SAVIOR/
├── backend/                 # Django backend
│   ├── savior_backend/      # Main Django project
│   ├── authentication/      # Authentication & role-based access control
│   ├── scanning/           # Vulnerability scanning module
│   ├── ai_risk_scoring/    # AI risk assessment module
│   ├── reporting/          # Report generation module
│   ├── integrations/       # Third-party integrations module
│   └── requirements.txt    # Python dependencies
├── frontend/               # React frontend
│   ├── public/
│   ├── src/
│   │   ├── components/     # Reusable React components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API service layer
│   │   └── contexts/       # React contexts
│   └── package.json        # Node dependencies
└── README.md
```

## 🚀 Features

- **Vulnerability Scanning**: Comprehensive scanning for web apps, APIs, networks, and containers
- **AI Risk Scoring**: Intelligent risk assessment using AI models
- **Reporting**: Generate detailed reports in multiple formats (PDF, HTML, JSON, CSV)
- **Integrations**: Connect with Slack, JIRA, GitHub, and other tools
- **Real-time Monitoring**: Track scan progress and vulnerability status
- **Role-Based Access Control**: Three user roles (Security Analyst, Compliance Officer, SOC Manager) with granular permissions

## 📋 Prerequisites

- Python 3.8+
- Node.js 14+
- MongoDB 4.4+
- pip (Python package manager)
- npm or yarn (Node package manager)

## 🔧 Installation

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
   - On Windows:
   ```bash
   venv\Scripts\activate
   ```
   - On macOS/Linux:
   ```bash
   source venv/bin/activate
   ```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Create a `.env` file in the `backend` directory (copy from `.env.example`):
```bash
cp .env.example .env
```

6. Update the `.env` file with your MongoDB connection details and Django secret key.

7. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

8. Create default users with roles:
```bash
python manage.py create_roles
```

This creates three default users:
- Security Analyst: `analyst` / `analyst123`
- Compliance Officer: `compliance` / `compliance123`
- SOC Manager: `soc_manager` / `soc123`

Alternatively, create a superuser:
```bash
python manage.py createsuperuser
```

9. Start the development server:
```bash
python manage.py runserver
```

The backend will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the `frontend` directory:
```bash
REACT_APP_API_URL=http://localhost:8000
```

4. Start the development server:
```bash
npm start
```

The frontend will be available at `http://localhost:3000`

## 🗄️ Database Setup (MongoDB)

1. Install MongoDB if not already installed:
   - Download from [MongoDB Download Center](https://www.mongodb.com/try/download/community)

2. Start MongoDB service:
   - On Windows: MongoDB should start automatically as a service
   - On macOS: `brew services start mongodb-community`
   - On Linux: `sudo systemctl start mongod`

3. Configure MongoDB connection in `.env` file:
```bash
MONGODB_NAME=savior_db
MONGODB_HOST=mongodb://localhost:27017/
MONGODB_USER=your_username
MONGODB_PASSWORD=your_password
MONGODB_AUTH_SOURCE=admin
```

4. For secure connections (production), enable SSL/TLS:
```bash
MONGODB_SSL=True
MONGODB_SSL_CERT_REQS=CERT_REQUIRED
MONGODB_SSL_CA_CERTS=/path/to/ca-cert.pem
```

5. Create MongoDB indexes for optimal performance:
```bash
python manage.py create_mongodb_indexes
```

6. Create a database (optional, Django will create it automatically):
```bash
mongosh
use savior_db
```

## 📚 API Documentation

Once the backend is running, you can access:
- Django Admin: `http://localhost:8000/admin`
- API Root: `http://localhost:8000/api/`

### API Endpoints

- **Authentication**: `/api/auth/`
  - Register: `POST /api/auth/register/`
  - Login: `POST /api/auth/login/`
  - Logout: `POST /api/auth/logout/`
  - Profile: `GET /api/auth/profile/`
  - Update Profile: `PUT /api/auth/profile/update/`
  - Change Password: `POST /api/auth/change-password/`
  - List Users: `GET /api/auth/users/` (SOC Manager only)

- **Scanning**: `/api/scanning/`
  - Targets: `/api/scanning/targets/`
  - Scans: `/api/scanning/scans/`
  - Vulnerabilities: `/api/scanning/vulnerabilities/`

- **AI Risk Scoring**: `/api/ai-risk/`
  - Risk Scores: `/api/ai-risk/scores/`
  - Risk Assessments: `/api/ai-risk/assessments/`
  - AI Models: `/api/ai-risk/models/`

- **Reporting**: `/api/reporting/`
  - Reports: `/api/reporting/reports/`
  - Templates: `/api/reporting/templates/`
  - Schedules: `/api/reporting/schedules/`

- **Integrations**: `/api/integrations/`
  - Integrations: `/api/integrations/integrations/`
  - Events: `/api/integrations/events/`
  - Webhooks: `/api/integrations/webhooks/`

## 👥 User Roles

SAVIOR supports three role-based access levels:

1. **Security Analyst** (`security_analyst`)
   - Perform vulnerability scans
   - View and manage scan results
   - Generate reports
   - View vulnerabilities

2. **Compliance Officer** (`compliance_officer`)
   - View compliance reports
   - Manage report templates
   - Schedule reports
   - View risk assessments

3. **SOC Manager** (`soc_manager`)
   - Full access to all features
   - Manage users
   - Configure integrations
   - View all scans and reports
   - Administrative privileges

## 🧪 Testing

### Backend Tests
```bash
cd backend
python manage.py test
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 🏭 Production Deployment

### Backend
1. Set `DEBUG=False` in `.env`
2. Set a strong `SECRET_KEY`
3. Configure proper `ALLOWED_HOSTS`
4. Use a production WSGI server (e.g., Gunicorn)
5. Set up proper MongoDB authentication

### Frontend
1. Build the production bundle:
```bash
npm run build
```
2. Serve the `build` directory using a web server (Nginx, Apache, etc.)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions, please open an issue on the repository.

## 🔒 MongoDB Security Features

- **Secure Connection Handling**: SSL/TLS support for encrypted connections
- **Connection Pooling**: Optimized connection pool settings
- **Authentication**: Support for SCRAM-SHA-1 and other auth mechanisms
- **Indexed Collections**: Performance-optimized indexes for fast queries
- **Data Models**: Structured storage for:
  - Vulnerability scan results
  - CVE (Common Vulnerabilities and Exposures) data
  - AI risk scores and assessments
  - Complete scan history

## 📊 Data Storage

The application uses MongoDB to store:
- **Vulnerability Scan Results**: Complete scan data with evidence and metadata
- **CVE Data**: Comprehensive CVE information including CVSS scores, descriptions, and references
- **AI Risk Scores**: AI-generated risk assessments with detailed analysis
- **Scan History**: Full audit trail of all scans with timestamps and status

## 🔮 Future Enhancements

- [ ] Real-time scan execution engine
- [ ] Advanced AI model integration
- [ ] Multi-tenant support
- [ ] Advanced reporting templates
- [ ] CI/CD pipeline integration
- [ ] Container scanning capabilities
- [ ] API security scanning
- [ ] Compliance reporting
- [ ] CVE data synchronization from external APIs

