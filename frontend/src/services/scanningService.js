import api from './api';

export const scanningService = {
  // Scan Targets
  getTargets: () => api.get('/api/scanning/targets/'),
  getTarget: (id) => api.get(`/api/scanning/targets/${id}/`),
  createTarget: (data) => api.post('/api/scanning/targets/', data),
  updateTarget: (id, data) => api.put(`/api/scanning/targets/${id}/`, data),
  deleteTarget: (id) => api.delete(`/api/scanning/targets/${id}/`),

  // Scans
  getScans: () => api.get('/api/scanning/scans/'),
  getScan: (id) => api.get(`/api/scanning/scans/${id}/`),
  createScan: (data) => api.post('/api/scanning/scans/', data),
  startScan: (id) => api.post(`/api/scanning/scans/${id}/start/`),
  cancelScan: (id) => api.post(`/api/scanning/scans/${id}/cancel/`),
  getScanVulnerabilities: (id) => api.get(`/api/scanning/scans/${id}/vulnerabilities/`),

  // Vulnerabilities
  getVulnerabilities: () => api.get('/api/scanning/vulnerabilities/'),
  getVulnerability: (id) => api.get(`/api/scanning/vulnerabilities/${id}/`),
  updateVulnerability: (id, data) => api.put(`/api/scanning/vulnerabilities/${id}/`, data),
  markFalsePositive: (id) => api.post(`/api/scanning/vulnerabilities/${id}/mark_false_positive/`),
};

