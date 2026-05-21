
import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import AlertPopover from '../AlertPopover/AlertPopover';
import {
  canAccessScanning,
  canAccessRiskScoring,
  canAccessReports,
  canAccessIntegrations,
  canAccessAlerts,
} from '../../utils/roles';
import './Layout.css';

const Layout = () => {
  const { logout, user } = useAuth();
  const location = useLocation();

  const isActive = (path) => location.pathname === path || location.pathname.startsWith(path + '/');

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <h1>SAVIOR</h1>
          <p>AI Vulnerability Scanner</p>
        </div>
        <ul className="nav-menu">
          <li>
            <Link to="/" className={isActive('/') && location.pathname === '/' ? 'active' : ''}>
              Dashboard
            </Link>
          </li>
          {canAccessScanning(user) && (
            <li>
              <Link to="/scanning" className={isActive('/scanning') ? 'active' : ''}>
                Scanning
              </Link>
              {isActive('/scanning') && (
                <ul className="submenu">
                  <li>
                    <Link to="/scanning/targets">Targets</Link>
                  </li>
                  <li>
                    <Link to="/scanning/scans">Scans</Link>
                  </li>
                  <li>
                    <Link to="/scanning/vulnerabilities">Vulnerabilities</Link>
                  </li>
                </ul>
              )}
            </li>
          )}
          {canAccessRiskScoring(user) && (
            <li>
              <Link to="/risk-scoring" className={isActive('/risk-scoring') ? 'active' : ''}>
                AI Risk Scoring
              </Link>
            </li>
          )}
          {canAccessReports(user) && (
            <li>
              <Link to="/reports" className={isActive('/reports') ? 'active' : ''}>
                Reports
              </Link>
            </li>
          )}
          {canAccessIntegrations(user) && (
            <li>
              <Link to="/integrations" className={isActive('/integrations') ? 'active' : ''}>
                Integrations
              </Link>
            </li>
          )}
          {canAccessAlerts(user) && (
            <li>
              <Link to="/alerts" className={isActive('/alerts') ? 'active' : ''}>
                Alerts
              </Link>
            </li>
          )}
        </ul>
        <div className="sidebar-footer">
          <p>Welcome, {user?.username || 'User'}</p>
          <button onClick={logout} className="btn-danger">Logout</button>
        </div>
      </nav>
      <main className="main-content">
        <Outlet />
      </main>
      <AlertPopover />
    </div>
  );
};

export default Layout;

