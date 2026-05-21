import React, { useEffect, useState } from 'react';
import { alertsService } from '../../services/alertsService';
import './Alerts.css';

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [ackInProgress, setAckInProgress] = useState(null);

  const fetchAlerts = async () => {
    try {
      const response = await alertsService.getAlerts();
      const data = response.data.results || response.data;
      setAlerts(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleAcknowledge = async (id) => {
    setAckInProgress(id);
    try {
      await alertsService.acknowledgeAlert(id);
      await fetchAlerts();
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to acknowledge alert');
    } finally {
      setAckInProgress(null);
    }
  };

  return (
    <div className="alerts-page">
      <div className="page-header">
        <h1>Alerts</h1>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {loading ? (
        <div className="loading">Loading alerts...</div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Type</th>
                <th>Channel</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Sent</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center' }}>
                    No alerts found.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.title}</td>
                    <td>{alert.alert_type}</td>
                    <td>{alert.channel}</td>
                    <td>{alert.status}</td>
                    <td>{alert.severity}</td>
                    <td>{alert.sent_at ? new Date(alert.sent_at).toLocaleString() : 'N/A'}</td>
                    <td>
                      <button
                        className="btn-sm btn-success"
                        onClick={() => handleAcknowledge(alert.id)}
                        disabled={ackInProgress === alert.id || alert.status === 'acknowledged'}
                      >
                        {alert.status === 'acknowledged' ? 'Acknowledged' : ackInProgress === alert.id ? 'Working...' : 'Acknowledge'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Alerts;
