import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanningService } from '../../services/scanningService';
import './Scanning.css';

const Scans = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    target: '',
    scan_type: 'web',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [startingScanId, setStartingScanId] = useState(null);

  useEffect(() => {
    fetchScans();
    fetchTargets();
  }, []);

  // Continuous polling for running scans
  useEffect(() => {
    const interval = setInterval(() => {
      const runningScans = scans.filter(scan => scan.status === 'running');
      if (runningScans.length > 0) {
        fetchScans();
      }
    }, 5000); // Poll every 5 seconds

    return () => clearInterval(interval);
  }, [scans]);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await scanningService.getScans();
      console.log('Scans API response:', response);
      const data = response.data.results || response.data || [];
      console.log('Parsed scans data:', data, 'Length:', Array.isArray(data) ? data.length : 'Not an array');
      setScans(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching scans:', error);
      console.error('Error details:', error.response?.data || error.message);
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchTargets = async () => {
    try {
      const response = await scanningService.getTargets();
      console.log('Targets for scan form:', response);
      const data = response.data.results || response.data || [];
      setTargets(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching targets:', error);
      setTargets([]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setIsSubmitting(true);

    try {
      if (!formData.target) {
        setErrorMessage('Please select a target');
        setIsSubmitting(false);
        return;
      }

      const response = await scanningService.createScan({
        target: parseInt(formData.target),
        scan_type: formData.scan_type,
      });
      
      setSuccessMessage('Scan created successfully!');
      setShowForm(false);
      setFormData({ target: '', scan_type: 'web' });
      fetchScans();
    } catch (error) {
      console.error('Error creating scan:', error);
      setErrorMessage(
        error.response?.data?.error || 
        error.response?.data?.detail || 
        'Failed to create scan. Please try again.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStartScan = async (scanId) => {
    setStartingScanId(scanId);
    setErrorMessage('');
    setSuccessMessage('');
    try {
      const response = await scanningService.startScan(scanId);
      console.log('Scan start response:', response.data);
      
      if (response.data.status === 'completed') {
        setSuccessMessage(`Scan completed! Found ${response.data.vulnerabilities_found || 0} vulnerabilities.`);
      } else if (response.data.status === 'running') {
        setSuccessMessage('Scan started! It may take a few moments to complete.');
      } else {
        setErrorMessage(response.data.error || 'Scan completed with issues.');
      }
      
      // Refresh scans immediately and then again after delay
      fetchScans();
      setTimeout(() => {
        fetchScans();
      }, 3000);
    } catch (error) {
      console.error('Error starting scan:', error);
      const errorMsg = error.response?.data?.error || error.response?.data?.detail || 'Failed to start scan';
      setErrorMessage(errorMsg);
      alert(errorMsg);
      fetchScans(); // Refresh to see updated status
    } finally {
      setStartingScanId(null);
    }
  };

  return (
    <div className="scanning-page">
      <div className="page-header">
        <h1>Scans</h1>
        <button 
          className="btn-primary" 
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? 'Cancel' : 'Create Scan'}
        </button>
      </div>

      {(errorMessage || successMessage) && !showForm && (
        <div style={{
          padding: '12px',
          margin: '10px 0',
          backgroundColor: errorMessage ? '#fee' : '#efe',
          color: errorMessage ? '#c33' : '#3c3',
          border: `1px solid ${errorMessage ? '#c33' : '#3c3'}`,
          borderRadius: '4px'
        }}>
          <strong>{errorMessage ? 'Error:' : 'Success:'}</strong> {errorMessage || successMessage}
        </div>
      )}

      {showForm && (
        <form onSubmit={handleSubmit} className="form-card">
          <h2>Create New Scan</h2>
          {errorMessage && <p className="error-message">{errorMessage}</p>}
          {successMessage && <p className="success-message">{successMessage}</p>}

          <div className="form-group">
            <label>Select Target:</label>
            <select
              name="target"
              value={formData.target}
              onChange={(e) => setFormData({ ...formData, target: e.target.value })}
              required
            >
              <option value="">-- Select a Target --</option>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} - {target.target_url || 'No URL'}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Scan Type:</label>
            <select
              name="scan_type"
              value={formData.scan_type}
              onChange={(e) => setFormData({ ...formData, scan_type: e.target.value })}
              required
            >
              <option value="web">Web Application</option>
              <option value="network">Network</option>
              <option value="api">API</option>
              <option value="code">Source Code</option>
              <option value="container">Container</option>
            </select>
          </div>

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Creating...' : 'Create Scan'}
          </button>
        </form>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Type</th>
              <th>Status</th>
              <th>Started</th>
              <th>Vulnerabilities</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
                  {loading ? 'Loading scans...' : 'No scans created yet. Click "Create Scan" to start.'}
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.id}>
                  <td>{scan.target_name || 'N/A'}</td>
                  <td>{scan.scan_type || 'N/A'}</td>
                  <td>
                    <span className={`status-badge status-${scan.status || 'pending'}`}>
                      {scan.status || 'pending'}
                    </span>
                  </td>
                  <td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}</td>
                  <td>{scan.vulnerability_count || 0}</td>
                  <td>
                    {scan.status === 'pending' && (
                      <button
                        onClick={() => handleStartScan(scan.id)}
                        className="btn-sm btn-success"
                        disabled={startingScanId === scan.id}
                      >
                        {startingScanId === scan.id ? 'Starting...' : 'Start'}
                      </button>
                    )}
                    {scan.status === 'running' && (
                      <span className="status-badge">Running...</span>
                    )}
                    {scan.status === 'completed' && (
                      <button
                        onClick={() => navigate(`/scanning/vulnerabilities?scan=${scan.id}`)}
                        className="btn-sm btn-secondary"
                      >
                        View Results
                      </button>
                    )}
                    {scan.status === 'failed' && (
                      <button
                        onClick={() => handleStartScan(scan.id)}
                        className="btn-sm btn-warning"
                        disabled={startingScanId === scan.id}
                        title={scan.error_message || 'Retry scan'}
                      >
                        Retry
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Scans;

