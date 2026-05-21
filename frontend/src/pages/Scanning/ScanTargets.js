import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanningService } from '../../services/scanningService';
import './Scanning.css';

const ScanTargets = () => {
  const navigate = useNavigate();
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    target_url: '',
    target_type: 'web',
    description: '',
  });

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      setError(null);
      setLoading(true);
      const response = await scanningService.getTargets();
      console.log('Targets API response:', response);
      const data = response.data.results || response.data || [];
      console.log('Parsed targets data:', data, 'Length:', Array.isArray(data) ? data.length : 'Not an array');
      setTargets(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching targets:', error);
      console.error('Error details:', error.response?.data || error.message);
      setError('Failed to load targets. Please check your connection and try again.');
      setTargets([]);
      if (error.response) {
        console.error('Response error:', error.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleViewVulnerabilities = async (target) => {
    try {
      // Get scans for this target
      const response = await scanningService.getScans();
      const scans = response.data.results || response.data || [];
      const targetScans = scans.filter(scan => scan.target && scan.target.id === target.id);
      
      if (targetScans.length > 0) {
        // Navigate to vulnerabilities page with the latest completed scan
        const latestScan = targetScans
          .filter(scan => scan.status === 'completed')
          .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at))[0];
        
        if (latestScan) {
          navigate(`/scanning/vulnerabilities?scan=${latestScan.id}`);
        } else {
          // If no completed scan, use the most recent scan
          const mostRecentScan = targetScans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
          navigate(`/scanning/vulnerabilities?scan=${mostRecentScan.id}`);
        }
      } else {
        // No scans found for this target, navigate to general vulnerabilities page
        navigate('/scanning/vulnerabilities');
      }
    } catch (error) {
      console.error('Error fetching scans for target:', error);
      // Fallback to general vulnerabilities page
      navigate('/scanning/vulnerabilities');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSubmitting(true);
    
    try {
      const response = await scanningService.createTarget(formData);
      console.log('Target created successfully:', response.data);
      setSuccess('Target created successfully!');
      setShowForm(false);
      setFormData({ name: '', target_url: '', target_type: 'web', description: '' });
      // Refresh the list
      await fetchTargets();
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(null), 3000);
    } catch (error) {
      console.error('Error creating target:', error);
      if (error.response) {
        // Server responded with error
        const errorData = error.response.data;
        if (errorData.detail) {
          setError(errorData.detail);
        } else if (errorData.error) {
          setError(errorData.error);
        } else if (typeof errorData === 'string') {
          setError(errorData);
        } else {
          // Handle validation errors
          const errorMessages = Object.entries(errorData)
            .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
            .join('\n');
          setError(errorMessages || 'Failed to create target. Please check your input.');
        }
        console.error('Error response:', error.response.data);
      } else if (error.request) {
        // Request made but no response
        setError('No response from server. Please check if the backend is running.');
        console.error('No response:', error.request);
      } else {
        // Something else happened
        setError('An unexpected error occurred. Please try again.');
        console.error('Error:', error.message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && targets.length === 0) {
    return <div style={{ padding: '20px', textAlign: 'center' }}>Loading targets...</div>;
  }

  return (
    <div className="scanning-page">
      <div className="page-header">
        <h1>Scan Targets</h1>
        <button onClick={() => {
          setShowForm(!showForm);
          setError(null);
          setSuccess(null);
        }} className="btn-primary">
          {showForm ? 'Cancel' : 'Add Target'}
        </button>
      </div>

      {error && (
        <div style={{
          padding: '12px',
          margin: '10px 0',
          backgroundColor: '#fee',
          color: '#c33',
          border: '1px solid #c33',
          borderRadius: '4px'
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {success && (
        <div style={{
          padding: '12px',
          margin: '10px 0',
          backgroundColor: '#efe',
          color: '#3c3',
          border: '1px solid #3c3',
          borderRadius: '4px'
        }}>
          <strong>Success:</strong> {success}
        </div>
      )}

      {showForm && (
        <form onSubmit={handleSubmit} className="form-card">
          <h2>New Scan Target</h2>
          <div className="form-group">
            <label>Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Target URL</label>
            <input
              type="url"
              value={formData.target_url}
              onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Target Type</label>
            <select
              value={formData.target_type}
              onChange={(e) => setFormData({ ...formData, target_type: e.target.value })}
            >
              <option value="web">Web Application</option>
              <option value="network">Network</option>
              <option value="api">API</option>
              <option value="code">Source Code</option>
              <option value="container">Container</option>
            </select>
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
          </div>
          <button 
            type="submit" 
            className="btn-primary"
            disabled={submitting}
          >
            {submitting ? 'Creating...' : 'Create Target'}
          </button>
        </form>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>URL</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {targets.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
                  {loading ? 'Loading targets...' : 'No targets found. Click "Add Target" to create your first target.'}
                </td>
              </tr>
            ) : (
              targets.map((target) => (
                <tr key={target.id}>
                  <td>{target.name || 'N/A'}</td>
                  <td>{target.target_type || 'N/A'}</td>
                  <td>{target.target_url || '-'}</td>
                  <td>{target.created_at ? new Date(target.created_at).toLocaleDateString() : 'N/A'}</td>
                  <td>
                    <button 
                      className="btn-sm btn-secondary"
                      onClick={() => handleViewVulnerabilities(target)}
                    >
                      View
                    </button>
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

export default ScanTargets;

