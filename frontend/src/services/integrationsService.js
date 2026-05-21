import api from './api';

export const integrationsService = {
  // Integrations
  getIntegrations: () => api.get('/api/integrations/integrations/'),
  getIntegration: (id) => api.get(`/api/integrations/integrations/${id}/`),
  createIntegration: (data) => api.post('/api/integrations/integrations/', data),
  updateIntegration: (id, data) => api.put(`/api/integrations/integrations/${id}/`, data),
  deleteIntegration: (id) => api.delete(`/api/integrations/integrations/${id}/`),
  testIntegration: (id) => api.post(`/api/integrations/integrations/${id}/test/`),
  syncIntegration: (id) => api.post(`/api/integrations/integrations/${id}/sync/`),
  toggleIntegration: (id) => api.post(`/api/integrations/integrations/${id}/toggle/`),

  // Integration Events
  getEvents: () => api.get('/api/integrations/events/'),
  getEvent: (id) => api.get(`/api/integrations/events/${id}/`),

  // Webhooks
  getWebhooks: () => api.get('/api/integrations/webhooks/'),
  getWebhook: (id) => api.get(`/api/integrations/webhooks/${id}/`),
  createWebhook: (data) => api.post('/api/integrations/webhooks/', data),
  updateWebhook: (id, data) => api.put(`/api/integrations/webhooks/${id}/`, data),
  deleteWebhook: (id) => api.delete(`/api/integrations/webhooks/${id}/`),
  testWebhook: (id) => api.post(`/api/integrations/webhooks/${id}/test/`),
};

