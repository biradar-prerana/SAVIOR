import api from './api';

export const reportingService = {
  // Reports
  getReports: () => api.get('/api/reporting/reports/'),
  getReport: (id) => api.get(`/api/reporting/reports/${id}/`),
  generateReport: (data) => api.post('/api/reporting/reports/generate/', data),
  downloadReport: (id) => api.get(`/api/reporting/reports/${id}/download/`, { responseType: 'blob' }),

  // Report Templates
  getTemplates: () => api.get('/api/reporting/templates/'),
  getTemplate: (id) => api.get(`/api/reporting/templates/${id}/`),
  createTemplate: (data) => api.post('/api/reporting/templates/', data),
  updateTemplate: (id, data) => api.put(`/api/reporting/templates/${id}/`, data),
  deleteTemplate: (id) => api.delete(`/api/reporting/templates/${id}/`),

  // Report Schedules
  getSchedules: () => api.get('/api/reporting/schedules/'),
  getSchedule: (id) => api.get(`/api/reporting/schedules/${id}/`),
  createSchedule: (data) => api.post('/api/reporting/schedules/', data),
  updateSchedule: (id, data) => api.put(`/api/reporting/schedules/${id}/`, data),
  deleteSchedule: (id) => api.delete(`/api/reporting/schedules/${id}/`),
  toggleSchedule: (id) => api.post(`/api/reporting/schedules/${id}/toggle/`),
};
