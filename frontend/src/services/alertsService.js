import api from './api';

export const alertsService = {
  getAlerts: () => api.get('/api/alerts/alerts/'),
  acknowledgeAlert: (id) => api.post(`/api/alerts/alerts/${id}/acknowledge/`),
  sendAlert: (data) => api.post('/api/alerts/alerts/send_alert/', data),
  getRules: () => api.get('/api/alerts/rules/'),
};
