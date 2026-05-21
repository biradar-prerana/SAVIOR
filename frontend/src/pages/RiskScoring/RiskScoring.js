import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { riskScoringService } from '../../services/riskScoringService';
import { scanningService } from '../../services/scanningService';
import './RiskScoring.css';

const RiskScoring = () => {
  const [assessments, setAssessments] = useState([]);
  const [riskScores, setRiskScores] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [selectedScan, setSelectedScan] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [activeTab, setActiveTab] = useState('assessments'); // 'assessments' or 'vulnerabilities'

  useEffect(() => {
    fetchAssessments();
    fetchRiskScores();
    fetchVulnerabilities();
    fetchScans();
  }, []);

  const fetchAssessments = async () => {
    try {
      const response = await riskScoringService.getAssessments();
      setAssessments(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching assessments:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchRiskScores = async () => {
    try {
      const response = await riskScoringService.getRiskScores();
      setRiskScores(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching risk scores:', error);
    }
  };

  const fetchVulnerabilities = async () => {
    try {
      const response = await scanningService.getVulnerabilities();
      const vulns = response.data.results || response.data;
      setVulnerabilities(vulns);
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
    }
  };

  const fetchScans = async () => {
    try {
      const response = await scanningService.getScans();
      setScans(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const handleCalculateRiskScore = async (vulnerabilityId) => {
    try {
      await riskScoringService.calculateRiskScore(vulnerabilityId);
      setSuccessMessage('Risk score calculated successfully!');
      // Refresh data
      fetchRiskScores();
      fetchVulnerabilities();
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(''), 5000);
    } catch (error) {
      console.error('Error calculating risk score:', error);
      setErrorMessage(error.response?.data?.error || 'Failed to calculate risk score');
      // Clear error message after 5 seconds
      setTimeout(() => setErrorMessage(''), 5000);
    }
  };

  const handleGenerateAssessment = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setIsGenerating(true);

    try {
      if (!selectedScan) {
        setErrorMessage('Please select a scan');
        setIsGenerating(false);
        return;
      }

      const response = await riskScoringService.generateAssessment(parseInt(selectedScan));
      setSuccessMessage('Risk assessment generated successfully!');
      setShowForm(false);
      setSelectedScan('');
      fetchAssessments(); // Refresh the list
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(''), 5000);
    } catch (error) {
      console.error('Error generating assessment:', error);
      setErrorMessage(
        error.response?.data?.error || 
        error.response?.data?.detail || 
        'Failed to generate assessment. Please try again.'
      );
      // Clear error message after 5 seconds
      setTimeout(() => setErrorMessage(''), 5000);
    } finally {
      setIsGenerating(false);
    }
  };

  const getRiskColor = (risk) => {
    const colors = {
      critical: '#e74c3c',
      high: '#e67e22',
      medium: '#f39c12',
      low: '#3498db',
      minimal: '#27ae60',
    };
    return colors[risk] || '#95a5a6';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#e74c3c',
      high: '#e67e22',
      medium: '#f39c12',
      low: '#3498db',
      info: '#95a5a6',
    };
    return colors[severity] || '#95a5a6';
  };

  const getRiskScoreColor = (score) => {
    if (score >= 80) return '#e74c3c'; // Critical - Red
    if (score >= 60) return '#e67e22'; // High - Orange
    if (score >= 40) return '#f39c12'; // Medium - Yellow
    if (score >= 20) return '#3498db'; // Low - Blue
    return '#27ae60'; // Minimal - Green
  };

  // Merge vulnerabilities with their risk scores
  const vulnerabilitiesWithScores = vulnerabilities.map(vuln => {
    const riskScore = riskScores.find(rs => rs.vulnerability?.id === vuln.id);
    return {
      ...vuln,
      riskScore: riskScore ? {
        overall_score: riskScore.overall_score,
        exploitability_score: riskScore.exploitability_score,
        impact_score: riskScore.impact_score,
        confidence: riskScore.confidence,
        ai_model_version: riskScore.ai_model_version,
        predicted_exploit_likelihood: riskScore.predicted_exploit_likelihood,
        remediation_priority: riskScore.remediation_priority,
      } : null
    };
  }).sort((a, b) => {
    // Sort by risk score (if available), then by severity
    if (a.riskScore && b.riskScore) {
      return b.riskScore.overall_score - a.riskScore.overall_score;
    }
    if (a.riskScore) return -1;
    if (b.riskScore) return 1;
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
  });

  if (loading) {
    return <div>Loading risk assessments...</div>;
  }

  return (
    <div className="risk-scoring-page">
      <div className="page-header">
        <h1>AI Risk Scoring</h1>
        <button 
          className="btn-primary" 
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? 'Cancel' : 'Generate Assessment'}
        </button>
      </div>

      {/* Tabs */}
      <div className="tabs-container">
        <button
          className={`tab-button ${activeTab === 'assessments' ? 'active' : ''}`}
          onClick={() => setActiveTab('assessments')}
        >
          Risk Assessments
        </button>
        <button
          className={`tab-button ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          Vulnerabilities with Risk Scores
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleGenerateAssessment} className="form-card">
          <h2>Generate Risk Assessment</h2>
          {errorMessage && <p className="error-message">{errorMessage}</p>}
          {successMessage && <p className="success-message">{successMessage}</p>}

          <div className="form-group">
            <label>Select Scan:</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              required
            >
              <option value="">-- Select a Scan --</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  Scan #{scan.id} - {scan.target_name} ({scan.status})
                </option>
              ))}
            </select>
          </div>

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isGenerating}
          >
            {isGenerating ? 'Generating...' : 'Generate Assessment'}
          </button>
        </form>
      )}

      {(errorMessage || successMessage) && (
        <div className="message-container">
          {errorMessage && <p className="error-message">{errorMessage}</p>}
          {successMessage && <p className="success-message">{successMessage}</p>}
        </div>
      )}

      {showForm && activeTab === 'assessments' && (
        <form onSubmit={handleGenerateAssessment} className="form-card">
          <h2>Generate Risk Assessment</h2>

          <div className="form-group">
            <label>Select Scan:</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              required
            >
              <option value="">-- Select a Scan --</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  Scan #{scan.id} - {scan.target_name} ({scan.status})
                </option>
              ))}
            </select>
          </div>

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isGenerating}
          >
            {isGenerating ? 'Generating...' : 'Generate Assessment'}
          </button>
        </form>
      )}

      {activeTab === 'assessments' && (
        <>
          {assessments.length === 0 ? (
            <div className="empty-state">
              <p>No risk assessments generated yet.</p>
              <p>Click "Generate Assessment" to create one for a scan.</p>
            </div>
          ) : (
            <div className="assessments-grid">
              {assessments.map((assessment) => (
                <div key={assessment.id} className="assessment-card">
                  <div className="assessment-header">
                    <h3>{assessment.scan_target_name || 'Risk Assessment'}</h3>
                    <span
                      className="risk-badge"
                      style={{ backgroundColor: getRiskColor(assessment.overall_risk) }}
                    >
                      {assessment.overall_risk}
                    </span>
                  </div>
                  <div className="risk-score">
                    <p className="score-value">{assessment.risk_score?.toFixed(1) || 'N/A'}</p>
                    <p className="score-label">Risk Score</p>
                  </div>
                  <div className="vulnerability-stats">
                    <div className="stat-item">
                      <span className="stat-label">Critical:</span>
                      <span className="stat-value critical">{assessment.critical_count || 0}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">High:</span>
                      <span className="stat-value high">{assessment.high_count || 0}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Medium:</span>
                      <span className="stat-value medium">{assessment.medium_count || 0}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Low:</span>
                      <span className="stat-value low">{assessment.low_count || 0}</span>
                    </div>
                  </div>
                  {assessment.recommendations && assessment.recommendations.length > 0 && (
                    <div className="recommendations">
                      <h4>Recommendations:</h4>
                      <ul>
                        {assessment.recommendations.slice(0, 3).map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="assessment-footer">
                    <p className="generated-date">
                      Generated: {new Date(assessment.generated_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {activeTab === 'vulnerabilities' && (
        <div className="vulnerabilities-with-scores">
          <div className="section-header">
            <h2>Vulnerabilities with AI Risk Scores</h2>
            <p className="section-description">
              View vulnerabilities with their AI-calculated risk scores. Click "Calculate Risk Score" to generate AI risk scores for vulnerabilities.
            </p>
          </div>

          {vulnerabilitiesWithScores.length === 0 ? (
            <div className="empty-state">
              <p>No vulnerabilities found.</p>
              <p>Run a scan to detect vulnerabilities first.</p>
            </div>
          ) : (
            <div className="vulnerability-scores-list">
              {vulnerabilitiesWithScores.map((vuln) => (
                <div key={vuln.id} className="vulnerability-score-card">
                  <div className="vulnerability-score-header">
                    <div className="vuln-title-section">
                      <Link to={`/vulnerabilities/${vuln.id}`} className="vuln-title">
                        {vuln.title}
                      </Link>
                      <span
                        className="severity-badge"
                        style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                      >
                        {vuln.severity}
                      </span>
                    </div>
                    {vuln.riskScore ? (
                      <div className="risk-score-display">
                        <div 
                          className="risk-score-circle"
                          style={{ 
                            borderColor: getRiskScoreColor(vuln.riskScore.overall_score),
                            color: getRiskScoreColor(vuln.riskScore.overall_score)
                          }}
                        >
                          <span className="risk-score-value">
                            {vuln.riskScore.overall_score.toFixed(1)}
                          </span>
                          <span className="risk-score-label">AI Risk Score</span>
                        </div>
                        <div className="risk-score-details">
                          <div className="risk-detail-item">
                            <span className="risk-detail-label">Exploitability:</span>
                            <span className="risk-detail-value">
                              {vuln.riskScore.exploitability_score.toFixed(1)}
                            </span>
                          </div>
                          <div className="risk-detail-item">
                            <span className="risk-detail-label">Impact:</span>
                            <span className="risk-detail-value">
                              {vuln.riskScore.impact_score.toFixed(1)}
                            </span>
                          </div>
                            {typeof vuln.riskScore.predicted_exploit_likelihood === 'number' && (
                              <div className="risk-detail-item">
                                <span className="risk-detail-label">Exploit Likelihood:</span>
                                <span className="risk-detail-value">
                                  {(vuln.riskScore.predicted_exploit_likelihood * 100).toFixed(1)}%
                                </span>
                              </div>
                            )}
                            {typeof vuln.riskScore.remediation_priority === 'number' && (
                              <div className="risk-detail-item">
                                <span className="risk-detail-label">Remediation Priority:</span>
                                <span className="risk-detail-value">
                                  {vuln.riskScore.remediation_priority}
                                </span>
                              </div>
                            )}
                          <div className="risk-detail-item">
                            <span className="risk-detail-label">Confidence:</span>
                            <span className="risk-detail-value">
                              {(vuln.riskScore.confidence * 100).toFixed(1)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <button
                        className="btn-sm btn-primary"
                        onClick={() => handleCalculateRiskScore(vuln.id)}
                      >
                        Calculate Risk Score
                      </button>
                    )}
                  </div>

                  <div className="vulnerability-details">
                    <div className="detail-row">
                      <div className="detail-item">
                        <span className="detail-label">CVE ID:</span>
                        <span className="detail-value">{vuln.cve_id || 'N/A'}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">CVSS Score:</span>
                        <span className="detail-value">{vuln.cvss_score || 'N/A'}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Type:</span>
                        <span className="detail-value">{vuln.vulnerability_type || 'N/A'}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Location:</span>
                        <span className="detail-value">{vuln.location || 'N/A'}</span>
                      </div>
                    </div>
                    {vuln.description && (
                      <div className="vuln-description">
                        {vuln.description.substring(0, 200)}
                        {vuln.description.length > 200 && '...'}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default RiskScoring;

