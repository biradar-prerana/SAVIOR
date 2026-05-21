
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout/Layout';
import ProtectedRoute from './components/ProtectedRoute/ProtectedRoute';
import Dashboard from './pages/Dashboard/Dashboard';
import Scanning from './pages/Scanning/Scanning';
import ScanTargets from './pages/Scanning/ScanTargets';
import Scans from './pages/Scanning/Scans';
import Vulnerabilities from './pages/Scanning/Vulnerabilities';
import RiskScoring from './pages/RiskScoring/RiskScoring';
import Reports from './pages/Reporting/Reports';
import Integrations from './pages/Integrations/Integrations';
import Alerts from './pages/Alerts/Alerts';
import VulnerabilityDetail from './pages/VulnerabilityDetail/VulnerabilityDetail';
import Login from './pages/Auth/Login';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import {
  canAccessScanning,
  canAccessRiskScoring,
  canAccessReports,
  canAccessIntegrations,
  canAccessAlerts,
} from './utils/roles';

const PrivateRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <Layout />
              </PrivateRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="scanning" element={
              <ProtectedRoute accessCheck={canAccessScanning}>
                <Scanning />
              </ProtectedRoute>
            }>
              <Route path="targets" element={
                <ProtectedRoute accessCheck={canAccessScanning}>
                  <ScanTargets />
                </ProtectedRoute>
              } />
              <Route path="scans" element={
                <ProtectedRoute accessCheck={canAccessScanning}>
                  <Scans />
                </ProtectedRoute>
              } />
              <Route path="vulnerabilities" element={
                <ProtectedRoute accessCheck={canAccessScanning}>
                  <Vulnerabilities />
                </ProtectedRoute>
              } />
            </Route>
            <Route path="vulnerabilities/:id" element={
              <ProtectedRoute accessCheck={canAccessScanning}>
                <VulnerabilityDetail />
              </ProtectedRoute>
            } />
            <Route path="risk-scoring" element={
              <ProtectedRoute accessCheck={canAccessRiskScoring}>
                <RiskScoring />
              </ProtectedRoute>
            } />
            <Route path="reports" element={
              <ProtectedRoute accessCheck={canAccessReports}>
                <Reports />
              </ProtectedRoute>
            } />
            <Route path="integrations" element={
              <ProtectedRoute accessCheck={canAccessIntegrations}>
                <Integrations />
              </ProtectedRoute>
            } />
            <Route path="alerts" element={
              <ProtectedRoute accessCheck={canAccessAlerts}>
                <Alerts />
              </ProtectedRoute>
            } />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;

