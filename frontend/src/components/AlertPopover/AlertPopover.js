
import React, { useEffect, useState } from 'react';
import { alertsService } from '../../services/alertsService';
import './AlertPopover.css';

const AlertPopover = () => {
  const [unackAlerts, setUnackAlerts] = useState([]);
  const [visible, setVisible] = useState(true);

  const fetchUnacknowledged = async () => {
    try {
      const res = await alertsService.getAlerts();
      const data = res.data.results || res.data;
      const unack = Array.isArray(data)
        ? data.filter(a => a.status !== 'acknowledged').slice(0, 5)
        : [];
      setUnackAlerts(unack);
    } catch (e) {
      console.error('Failed to fetch alerts for popover', e);
    }
  };

  useEffect(() => {
    fetchUnacknowledged();
    const interval = setInterval(fetchUnacknowledged, 60000);
    return () => clearInterval(interval);
  }, []);

  const handleClose = (id) => {
    setUnackAlerts(prev => prev.filter(a => a.id !== id));
  };

  if (!visible || unackAlerts.length === 0) return null;

  return (
    <div className="alert-popover-wrapper">
      <div className="alert-popover-header">
        <strong>Alerts</strong>
        <button className="popover-minimize" onClick={() => setVisible(false)} aria-label="Minimize">
          ✕
        </button>
      </div>
      <div className="alert-popover-list">
        {unackAlerts.map(alert => (
          <div key={alert.id} className={`popover-alert-item popover-alert-${alert.severity || 'info'}`}>
            <div className="popover-alert-title">{alert.title}</div>
            <div className="popover-alert-meta">
              {alert.severity && <span className="popover-alert-severity">{alert.severity}</span>}
              <span className="popover-alert-type">{alert.alert_type}</span>
            </div>
            <button className="popover-alert-close" onClick={() => handleClose(alert.id)} aria-label="Close">
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AlertPopover;

