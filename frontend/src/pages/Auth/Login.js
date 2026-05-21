import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import './Login.css';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const result = await login(username, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error || 'Login failed');
    }
  };

  return (
    <div className="login-container">
      <div className="login-grid">
        <aside className="login-hero">
          <div className="brand">
            <div className="brand-mark">▶</div>
            <div>
              <h1>SAVIOR</h1>
              <p>AI Vulnerability Scanner</p>
            </div>
          </div>
          <div className="hero-graphic" aria-hidden="true">
            <div className="radar">
              <span className="ring r1"></span>
              <span className="ring r2"></span>
              <span className="ring r3"></span>
              <span className="sweep"></span>
            </div>
            <div className="nodes">
              <span className="node n1"></span>
              <span className="node n2"></span>
              <span className="node n3"></span>
              <span className="node n4"></span>
            </div>
          </div>
          <div className="feature-chips">
            <span>Web</span>
            <span>Network</span>
            <span>API</span>
            <span>Container</span>
            <span>Code</span>
          </div>
          <p className="legal">Authorized access only</p>
        </aside>
        <div className="login-card">
          <h2>Sign in</h2>
          <p>Secure dashboard for scans, alerts, and risk scoring</p>
          <form onSubmit={handleSubmit}>
            {error && <div className="error-message">{error}</div>}
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn-primary">Login</button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;

