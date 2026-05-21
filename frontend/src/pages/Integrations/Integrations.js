
import React, { useState, useEffect } from 'react';
import { integrationsService } from '../../services/integrationsService';
import './Integrations.css';

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    integration_type: 'jira',
    config: {},
    credentials: {},
    is_enabled: true,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [testingId, setTestingId] = useState(null);
  const [actionMessage, setActionMessage] = useState('');
  const [actionMessageType, setActionMessageType] = useState('');

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    try {
      const response = await integrationsService.getIntegrations();
      setIntegrations(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching integrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    if (name.startsWith('config.')) {
      const configKey = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        config: {
          ...prev.config,
          [configKey]: value,
        }
      }));
    } else if (name.startsWith('credentials.')) {
      const credKey = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        credentials: {
          ...prev.credentials,
          [credKey]: value,
        }
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setActionMessage('');
    setActionMessageType('');
    setIsSubmitting(true);

    try {
      const submissionData = {
        name: formData.name.trim(),
        integration_type: formData.integration_type,
        config: formData.config || {},
        credentials: formData.credentials || {},
        is_enabled: formData.is_enabled,
      };

      Object.keys(submissionData.config).forEach(key => {
        const value = submissionData.config[key];
        if (value === null || value === undefined || (typeof value === 'string' && value.trim() === '')) {
          delete submissionData.config[key];
        }
      });
      
      Object.keys(submissionData.credentials).forEach(key => {
        const value = submissionData.credentials[key];
        if (value === null || value === undefined || (typeof value === 'string' && value.trim() === '')) {
          delete submissionData.credentials[key];
        }
      });

      console.log('Submitting integration data:', submissionData);
      await integrationsService.createIntegration(submissionData);
      setSuccessMessage('Integration created successfully!');
      setShowForm(false);
      setFormData({
        name: '',
        integration_type: 'jira',
        config: {},
        credentials: {},
        is_enabled: true,
      });
      fetchIntegrations();
    } catch (error) {
      console.error('Error creating integration:', error);
      console.error('Error response:', error.response?.data);
      console.error('Form data being sent:', formData);
      
      let errorMsg = 'Failed to create integration. Please check your input and try again.';
      
      if (error.response?.data) {
        const errorData = error.response.data;
        if (errorData.error) {
          errorMsg = errorData.error;
        } else if (errorData.detail) {
          errorMsg = errorData.detail;
        } else if (errorData.non_field_errors) {
          errorMsg = Array.isArray(errorData.non_field_errors) 
            ? errorData.non_field_errors.join(', ') 
            : errorData.non_field_errors;
        } else if (typeof errorData === 'object') {
          const fieldErrors = Object.entries(errorData)
            .map(([field, messages]) => {
              const msg = Array.isArray(messages) ? messages.join(', ') : messages;
              return `${field}: ${msg}`;
            })
            .join('; ');
          if (fieldErrors) {
            errorMsg = fieldErrors;
          }
        }
      } else if (error.message) {
        errorMsg = error.message;
      }
      
      setErrorMessage(errorMsg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTest = async (id) => {
    setTestingId(id);
    setActionMessage('');
    setActionMessageType('');
    try {
      const response = await integrationsService.testIntegration(id);
      setActionMessage(response.data.message || 'Test completed successfully');
      setActionMessageType('success');
    } catch (error) {
      setActionMessage(error.response?.data?.message || 'Test failed');
      setActionMessageType('error');
    } finally {
      setTestingId(null);
      setTimeout(() => {
        setActionMessage('');
        setActionMessageType('');
      }, 4000);
    }
  };

  const handleSync = async (id) => {
    setActionMessage('');
    setActionMessageType('');
    try {
      await integrationsService.syncIntegration(id);
      setActionMessage('Sync initiated successfully');
      setActionMessageType('success');
      fetchIntegrations();
    } catch (error) {
      setActionMessage('Sync failed');
      setActionMessageType('error');
    } finally {
      setTimeout(() => {
        setActionMessage('');
        setActionMessageType('');
      }, 4000);
    }
  };

  const handleToggle = async (id) => {
    setActionMessage('');
    setActionMessageType('');
    try {
      await integrationsService.toggleIntegration(id);
      setActionMessage('Integration toggled successfully');
      setActionMessageType('success');
      fetchIntegrations();
    } catch (error) {
      setActionMessage('Failed to toggle integration');
      setActionMessageType('error');
    } finally {
      setTimeout(() => {
        setActionMessage('');
        setActionMessageType('');
      }, 4000);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      active: '#27ae60',
      inactive: '#95a5a6',
      error: '#e74c3c',
    };
    return colors[status] || '#95a5a6';
  };

  const getStatus = (integration) => {
    if (!integration.is_enabled) return 'inactive';
    return 'active';
  };

  if (loading) {
    return <div>Loading integrations...</div>;
  }

  return (
    <div className="integrations-page">
      <div className="page-header">
        <h1>Integrations</h1>
        <button 
          className="btn-primary" 
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? 'Cancel' : 'Add Integration'}
        </button>
      </div>

      {actionMessage && (
        <div className={`action-message ${actionMessageType}`}>
          <span style={{ flex: 1 }}>{actionMessage}</span>
          <button
            onClick={() => { setActionMessage(''); setActionMessageType(''); }}
            style={{
              background: 'transparent',
              border: 'none',
              color: actionMessageType === 'success' ? '#bbf7d0' : '#fecaca',
              fontSize: '16px',
              cursor: 'pointer',
              padding: '0 4px',
              marginLeft: '12px',
            }}
          >
            ✕
          </button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleSubmit} className="form-card">
          <h2>Create New Integration</h2>
          {errorMessage && <p className="error-message">{errorMessage}</p>}
          {successMessage && <p className="success-message">{successMessage}</p>}

          <div className="form-group">
            <label>Integration Name:</label>
            <input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              required
              placeholder="e.g., JIRA Production"
            />
          </div>

          <div className="form-group">
            <label>Integration Type:</label>
            <select
              name="integration_type"
              value={formData.integration_type}
              onChange={handleInputChange}
              required
            >
              <option value="jira">JIRA</option>
              <option value="servicenow">ServiceNow</option>
              <option value="custom">Custom</option>
            </select>
          </div>

          {formData.integration_type === 'jira' && (
            <>
              <div className="form-group">
                <label>JIRA Base URL:</label>
                <input
                  type="url"
                  name="config.base_url"
                  value={formData.config.base_url || ''}
                  onChange={handleInputChange}
                  placeholder="https://yourcompany.atlassian.net"
                />
              </div>
              <div className="form-group">
                <label>Project Key:</label>
                <input
                  type="text"
                  name="config.project_key"
                  value={formData.config.project_key || ''}
                  onChange={handleInputChange}
                  placeholder="SEC"
                />
              </div>
              <div className="form-group">
                <label>Username/Email:</label>
                <input
                  type="text"
                  name="credentials.username"
                  value={formData.credentials.username || ''}
                  onChange={handleInputChange}
                  placeholder="your-email@example.com"
                />
              </div>
              <div className="form-group">
                <label>API Token:</label>
                <input
                  type="password"
                  name="credentials.api_token"
                  value={formData.credentials.api_token || ''}
                  onChange={handleInputChange}
                  placeholder="Your JIRA API token"
                />
              </div>
            </>
          )}

          {formData.integration_type === 'servicenow' && (
            <>
              <div className="form-group">
                <label>Instance URL:</label>
                <input
                  type="url"
                  name="config.instance_url"
                  value={formData.config.instance_url || ''}
                  onChange={handleInputChange}
                  placeholder="https://yourinstance.service-now.com"
                />
              </div>
              <div className="form-group">
                <label>Table Name:</label>
                <input
                  type="text"
                  name="config.table_name"
                  value={formData.config.table_name || 'incident'}
                  onChange={handleInputChange}
                />
              </div>
              <div className="form-group">
                <label>Username:</label>
                <input
                  type="text"
                  name="credentials.username"
                  value={formData.credentials.username || ''}
                  onChange={handleInputChange}
                />
              </div>
              <div className="form-group">
                <label>Password:</label>
                <input
                  type="password"
                  name="credentials.password"
                  value={formData.credentials.password || ''}
                  onChange={handleInputChange}
                />
              </div>
            </>
          )}

          <div className="form-group">
            <label>
              <input
                type="checkbox"
                name="is_enabled"
                checked={formData.is_enabled}
                onChange={handleInputChange}
              />
              Enable Integration
            </label>
          </div>

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Creating...' : 'Create Integration'}
          </button>
        </form>
      )}

      {integrations.length === 0 ? (
        <div className="empty-state">
          <p>No integrations configured yet.</p>
          <p>Click "Add Integration" to create one.</p>
        </div>
      ) : (
        <div className="integrations-grid">
          {integrations.map((integration) => (
            <div key={integration.id} className="integration-card">
              <div className="integration-header">
                <h3>{integration.name}</h3>
                <span
                  className="status-badge"
                  style={{ backgroundColor: getStatusColor(getStatus(integration)) }}
                >
                  {getStatus(integration)}
                </span>
              </div>
              <p className="integration-type">{integration.integration_type}</p>
              {integration.last_sync && (
                <p className="last-sync">
                  Last Sync: {new Date(integration.last_sync).toLocaleString()}
                </p>
              )}
              <div className="integration-actions">
                <button 
                  className="btn-sm btn-secondary"
                  onClick={() => handleTest(integration.id)}
                  disabled={testingId === integration.id}
                >
                  {testingId === integration.id ? 'Testing...' : 'Test'}
                </button>
                <button 
                  className="btn-sm btn-primary"
                  onClick={() => handleSync(integration.id)}
                >
                  Sync
                </button>
                <button 
                  className="btn-sm btn-warning"
                  onClick={() => handleToggle(integration.id)}
                >
                  {integration.is_enabled ? 'Disable' : 'Enable'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Integrations;

