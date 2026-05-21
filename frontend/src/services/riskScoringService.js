import api from './api';

export const riskScoringService = {
  // Risk Scores
  getRiskScores: () => api.get('/api/ai-risk/scores/'),
  getRiskScore: (id) => api.get(`/api/ai-risk/scores/${id}/`),
  calculateRiskScore: (vulnerabilityId) =>
    api.post('/api/ai-risk/scores/calculate/', { vulnerability_id: vulnerabilityId }),

  // Risk Assessments
  getAssessments: () => api.get('/api/ai-risk/assessments/'),
  getAssessment: (id) => api.get(`/api/ai-risk/assessments/${id}/`),
  generateAssessment: (scanId) =>
    api.post('/api/ai-risk/assessments/generate/', { scan_id: scanId }),

  // AI Models
  getModels: () => api.get('/api/ai-risk/models/'),
  getModel: (id) => api.get(`/api/ai-risk/models/${id}/`),
};

