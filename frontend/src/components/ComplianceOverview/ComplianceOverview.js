import React, { useState, useEffect } from 'react';
import { scanningService } from '../../services/scanningService';
import { riskScoringService } from '../../services/riskScoringService';
import './ComplianceOverview.css';

const ComplianceOverview = () => {
  const [complianceData, setComplianceData] = useState({
    totalVulnerabilities: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    complianceScore: 0,
    riskLevel: 'unknown',
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchComplianceData();
  }, []);

  const fetchComplianceData = async () => {
    try {
      const [vulnsRes, assessmentsRes] = await Promise.all([
        scanningService.getVulnerabilities(),
        riskScoringService.getAssessments(),
      ]);

      const vulnerabilities = vulnsRes.data.results || vulnsRes.data;
      const assessments = assessmentsRes.data.results || assessmentsRes.data;

      const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
      const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
      const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
      const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;

      // Calculate compliance score (0-100)
      // Lower score = better compliance (fewer critical/high vulnerabilities)
      const total = vulnerabilities.length;
      const complianceScore = total > 0
        ? Math.max(0, 100 - ((criticalCount * 10 + highCount * 5 + mediumCount * 2) / total * 100))
        : 100;

      // Determine risk level
      let riskLevel = 'low';
      if (criticalCount > 0 || highCount > 5) {
        riskLevel = 'critical';
      } else if (highCount > 0 || mediumCount > 10) {
        riskLevel = 'high';
      } else if (mediumCount > 0 || lowCount > 20) {
        riskLevel = 'medium';
      }

      setComplianceData({
        totalVulnerabilities: total,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        complianceScore: Math.round(complianceScore),
        riskLevel,
      });
    } catch (error) {
      console.error('Error fetching compliance data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskLevelColor = (level) => {
    const colors = {
      critical: '#e74c3c',
      high: '#e67e22',
      medium: '#f39c12',
      low: '#27ae60',
      unknown: '#95a5a6',
    };
    return colors[level] || '#95a5a6';
  };

  const getComplianceStatus = (score) => {
    if (score >= 90) return { status: 'Excellent', color: '#27ae60' };
    if (score >= 75) return { status: 'Good', color: '#3498db' };
    if (score >= 60) return { status: 'Fair', color: '#f39c12' };
    if (score >= 40) return { status: 'Poor', color: '#e67e22' };
    return { status: 'Critical', color: '#e74c3c' };
  };

  if (loading) {
    return <div className="loading">Loading compliance data...</div>;
  }

  const complianceStatus = getComplianceStatus(complianceData.complianceScore);

  return (
    <div className="compliance-overview">
      <h2>Compliance Overview</h2>

      <div className="compliance-score-card">
        <div className="score-circle" style={{ borderColor: complianceStatus.color }}>
          <div className="score-value" style={{ color: complianceStatus.color }}>
            {complianceData.complianceScore}
          </div>
          <div className="score-label">Compliance Score</div>
        </div>
        <div className="compliance-status">
          <div className="status-label">Status:</div>
          <div className="status-value" style={{ color: complianceStatus.color }}>
            {complianceStatus.status}
          </div>
        </div>
        <div className="risk-level">
          <div className="risk-label">Risk Level:</div>
          <div
            className="risk-badge"
            style={{ backgroundColor: getRiskLevelColor(complianceData.riskLevel) }}
          >
            {complianceData.riskLevel.toUpperCase()}
          </div>
        </div>
      </div>

      <div className="compliance-breakdown">
        <h3>Vulnerability Breakdown</h3>
        <div className="breakdown-grid">
          <div className="breakdown-item critical">
            <div className="breakdown-number">{complianceData.criticalCount}</div>
            <div className="breakdown-label">Critical</div>
          </div>
          <div className="breakdown-item high">
            <div className="breakdown-number">{complianceData.highCount}</div>
            <div className="breakdown-label">High</div>
          </div>
          <div className="breakdown-item medium">
            <div className="breakdown-number">{complianceData.mediumCount}</div>
            <div className="breakdown-label">Medium</div>
          </div>
          <div className="breakdown-item low">
            <div className="breakdown-number">{complianceData.lowCount}</div>
            <div className="breakdown-label">Low</div>
          </div>
        </div>
      </div>

      <div className="compliance-actions">
        <h3>Recommended Actions</h3>
        <ul className="action-list">
          {complianceData.criticalCount > 0 && (
            <li className="action-item critical">
              <strong>Immediate Action Required:</strong> Address {complianceData.criticalCount} critical
              vulnerability(ies) immediately
            </li>
          )}
          {complianceData.highCount > 0 && (
            <li className="action-item high">
              <strong>High Priority:</strong> Review and remediate {complianceData.highCount} high severity
              vulnerability(ies) within 7 days
            </li>
          )}
          {complianceData.mediumCount > 5 && (
            <li className="action-item medium">
              <strong>Medium Priority:</strong> Plan remediation for {complianceData.mediumCount} medium severity
              vulnerabilities
            </li>
          )}
          {complianceData.complianceScore < 60 && (
            <li className="action-item">
              <strong>Compliance Risk:</strong> Current compliance score is below acceptable threshold.
              Immediate remediation required.
            </li>
          )}
          {complianceData.complianceScore >= 90 && (
            <li className="action-item success">
              <strong>Good Standing:</strong> Compliance score is excellent. Continue monitoring and
              maintain security posture.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
};

export default ComplianceOverview;

