import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { saveAs } from 'file-saver';
import { scanningService } from '../../services/scanningService';
import { riskScoringService } from '../../services/riskScoringService';
import { reportingService } from '../../services/reportingService';
import RiskScoreChart from '../../components/Charts/RiskScoreChart';
import SeverityChart from '../../components/Charts/SeverityChart';
import TrendChart from '../../components/Charts/TrendChart';
import ComplianceOverview from '../../components/ComplianceOverview/ComplianceOverview';
import VulnerabilityList from '../../components/VulnerabilityList/VulnerabilityList';
import { useAuth } from '../../contexts/AuthContext';
import { canAccessScanning } from '../../utils/roles';
import './Dashboard.css';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    activeScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    mediumVulnerabilities: 0,
    lowVulnerabilities: 0,
  });
  const [riskScores, setRiskScores] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false);
  const [pdfMessage, setPdfMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [scansRes, vulnerabilitiesRes, riskScoresRes] = await Promise.all([
        scanningService.getScans(),
        scanningService.getVulnerabilities(),
        riskScoringService.getRiskScores(),
      ]);

      const scans = scansRes.data.results || scansRes.data || [];
      const vulns = vulnerabilitiesRes.data.results || vulnerabilitiesRes.data || [];
      const scores = riskScoresRes.data.results || riskScoresRes.data || [];
      
      console.log('Dashboard - Fetched vulnerabilities:', vulns.length, vulns);
      setVulnerabilities(Array.isArray(vulns) ? vulns : []);

      // Calculate statistics
      const criticalCount = vulns.filter(v => v.severity === 'critical').length;
      const highCount = vulns.filter(v => v.severity === 'high').length;
      const mediumCount = vulns.filter(v => v.severity === 'medium').length;
      const lowCount = vulns.filter(v => v.severity === 'low').length;

      setStats({
        totalScans: scans.length,
        activeScans: scans.filter(s => s.status === 'running').length,
        totalVulnerabilities: vulns.length,
        criticalVulnerabilities: criticalCount,
        highVulnerabilities: highCount,
        mediumVulnerabilities: mediumCount,
        lowVulnerabilities: lowCount,
      });

      // Set risk scores for chart (top 10 by score)
      // Also check if vulnerabilities have risk_score data
      let allRiskScores = scores || [];
      
      console.log('Dashboard - Risk scores from API:', allRiskScores.length);
      
      // If no risk scores from API, try to extract from vulnerabilities
      if (allRiskScores.length === 0 && vulns.length > 0) {
        console.log('Dashboard - Checking vulnerabilities for embedded risk_score data...');
        const vulnsWithRiskScores = vulns.filter(v => {
          const hasRiskScore = v.risk_score && 
                               v.risk_score.overall_score !== undefined && 
                               v.risk_score.overall_score !== null;
          if (hasRiskScore) {
            console.log(`  - Vulnerability ${v.id} has risk_score:`, v.risk_score.overall_score);
          }
          return hasRiskScore;
        });
        
        console.log(`Dashboard - Found ${vulnsWithRiskScores.length} vulnerabilities with risk_score data`);
        
        allRiskScores = vulnsWithRiskScores.map(v => ({
          id: v.id,
          vulnerability_title: v.title,
          overall_score: v.risk_score.overall_score,
          exploitability_score: v.risk_score.exploitability_score || 0,
          impact_score: v.risk_score.impact_score || 0,
          confidence: v.risk_score.confidence || 0,
        }));
      }
      
      const topScores = allRiskScores
        .sort((a, b) => (b.overall_score || 0) - (a.overall_score || 0))
        .slice(0, 10);
      
      console.log('Dashboard - Final risk scores for chart:', topScores.length);
      setRiskScores(topScores);

      // Generate trend data (last 7 days)
      const trend = generateTrendData(vulns);
      setTrendData(trend);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateTrendData = (vulnerabilities) => {
    const days = 7;
    const today = new Date();
    const trend = [];

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

      const dayVulns = vulnerabilities.filter(v => {
        const vulnDate = new Date(v.detected_at);
        return vulnDate.toDateString() === date.toDateString();
      });

      trend.push({
        date: dateStr,
        critical: dayVulns.filter(v => v.severity === 'critical').length,
        high: dayVulns.filter(v => v.severity === 'high').length,
        medium: dayVulns.filter(v => v.severity === 'medium').length,
        low: dayVulns.filter(v => v.severity === 'low').length,
      });
    }

    return trend;
  };

  const handleGeneratePDF = async () => {
    if (vulnerabilities.length === 0) {
      setPdfMessage({ type: 'error', text: 'No vulnerabilities to export. Please run a scan first.' });
      setTimeout(() => setPdfMessage({ type: '', text: '' }), 5000);
      return;
    }

    setIsGeneratingPDF(true);
    setPdfMessage({ type: '', text: '' });

    try {
      const reportName = `Dashboard_Vulnerabilities_Report_${new Date().toISOString().split('T')[0]}`;
      const response = await reportingService.generateReport({
        all_vulnerabilities: true,
        report_type: 'dashboard',
        format: 'pdf',
        report_name: reportName,
      });

      // Download the report
      if (response.data.id) {
        const downloadResponse = await reportingService.downloadReport(response.data.id);
        const blob = new Blob([downloadResponse.data], { type: 'application/pdf' });
        saveAs(blob, `${reportName}.pdf`);
        setPdfMessage({ type: 'success', text: 'PDF report generated and downloaded successfully!' });
      } else {
        throw new Error('Report ID not returned');
      }
    } catch (error) {
      console.error('Error generating PDF:', error);
      setPdfMessage({
        type: 'error',
        text: error.response?.data?.error || 'Failed to generate PDF report. Please try again.',
      });
    } finally {
      setIsGeneratingPDF(false);
      setTimeout(() => setPdfMessage({ type: '', text: '' }), 5000);
    }
  };

  if (loading) {
    return <div className="dashboard-loading">Loading dashboard...</div>;
  }

  const severityData = {
    critical: stats.criticalVulnerabilities,
    high: stats.highVulnerabilities,
    medium: stats.mediumVulnerabilities,
    low: stats.lowVulnerabilities,
    info: 0,
  };

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <div className="header-actions">
          <div className="action-group">
            <button
              onClick={handleGeneratePDF}
              disabled={isGeneratingPDF || vulnerabilities.length === 0}
              className="btn-primary btn-export-pdf"
              title="Generate PDF report of all vulnerabilities"
            >
              {isGeneratingPDF ? (
                <>
                  <i className="fas fa-spinner fa-spin"></i> Generating PDF...
                </>
              ) : (
                <>
                  <i className="fas fa-file-pdf"></i> Export PDF Report
                </>
              )}
            </button>
          </div>
          <div className="action-group">
            <Link to="/scanning/vulnerabilities" className="view-all-link">
              <i className="fas fa-list"></i> View All Vulnerabilities
            </Link>
          </div>
        </div>
      </div>

      {pdfMessage.text && (
        <div className={`pdf-message ${pdfMessage.type}`}>
          {pdfMessage.text}
        </div>
      )}

      {/* Statistics Cards */}
      <div className="stats-section">
        <h2 className="section-title">Key Metrics</h2>
        <div className="stats-grid">
          <Link to="/scanning/scans" className="stat-card">
            <div className="stat-icon">
              <i className="fas fa-search"></i>
            </div>
            <h3>Total Scans</h3>
            <p className="stat-value">{stats.totalScans}</p>
          </Link>
          <Link to="/scanning/scans" className="stat-card">
            <div className="stat-icon active">
              <i className="fas fa-spinner fa-spin"></i>
            </div>
            <h3>Active Scans</h3>
            <p className="stat-value">{stats.activeScans}</p>
          </Link>
          <Link to="/scanning/vulnerabilities" className="stat-card">
            <div className="stat-icon">
              <i className="fas fa-shield-alt"></i>
            </div>
            <h3>Total Vulnerabilities</h3>
            <p className="stat-value">{stats.totalVulnerabilities}</p>
          </Link>
          <Link to="/scanning/vulnerabilities?severity=critical" className="stat-card critical">
            <div className="stat-icon">
              <i className="fas fa-exclamation-circle"></i>
            </div>
            <h3>Critical</h3>
            <p className="stat-value">{stats.criticalVulnerabilities}</p>
          </Link>
          <Link to="/scanning/vulnerabilities?severity=high" className="stat-card high">
            <div className="stat-icon">
              <i className="fas fa-exclamation-triangle"></i>
            </div>
            <h3>High</h3>
            <p className="stat-value">{stats.highVulnerabilities}</p>
          </Link>
          <Link to="/scanning/vulnerabilities?severity=medium" className="stat-card medium">
            <div className="stat-icon">
              <i className="fas fa-info-circle"></i>
            </div>
            <h3>Medium</h3>
            <p className="stat-value">{stats.mediumVulnerabilities}</p>
          </Link>
        </div>
      </div>

      {/* Charts Section */}
      <div className="charts-section">
        <h2 className="section-title">Analytics & Trends</h2>
        <div className="charts-row">
          <div className="chart-wrapper">
            <div className="chart-card">
              <SeverityChart data={severityData} />
            </div>
          </div>
          <div className="chart-wrapper">
            <div className="chart-card">
              {riskScores.length > 0 ? (
                <RiskScoreChart data={riskScores} />
              ) : (
                <div className="chart-container">
                  <h3>Risk Score Distribution</h3>
                  <div className="no-data">No risk score data available. Generate risk assessments to see distribution.</div>
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="charts-row">
          <div className="chart-wrapper full-width">
            <div className="chart-card">
              <TrendChart data={trendData} />
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Overview */}
      <div className="compliance-section">
        <ComplianceOverview />
      </div>

      {/* Vulnerabilities Section */}
      <div className="vulnerabilities-section">
        <div className="section-header">
          <h2>Vulnerabilities Overview</h2>
          <Link to="/scanning/vulnerabilities" className="view-all-link">
            View All →
          </Link>
        </div>
        
        {stats.totalVulnerabilities === 0 ? (
          <div className="empty-state-card">
            <p>No vulnerabilities detected yet.</p>
            <p>Start by creating a scan target and running a vulnerability scan.</p>
            <Link to="/scanning/targets" className="btn-primary" style={{ marginTop: '20px', display: 'inline-block' }}>
              Create Scan Target
            </Link>
          </div>
        ) : (
          <>
            {/* Critical & High Priority Section */}
            {(stats.criticalVulnerabilities > 0 || stats.highVulnerabilities > 0) && (
              <div className="priority-vulnerabilities">
                <h3 className="priority-header">
                  <span className="priority-icon critical">⚠</span>
                  Critical & High Priority Vulnerabilities
                  <span className="priority-count">
                    ({stats.criticalVulnerabilities + stats.highVulnerabilities})
                  </span>
                </h3>
                <VulnerabilityList 
                  limit={null} 
                  showFilters={false}
                  defaultSeverity={['critical', 'high']}
                />
              </div>
            )}

            {/* All Vulnerabilities Section */}
            <div className="all-vulnerabilities">
              <h3 className="all-vulnerabilities-header">
                <i className="fas fa-list"></i> All Discovered Vulnerabilities
                <span className="total-count-badge">
                  ({stats.totalVulnerabilities})
                </span>
              </h3>
              <VulnerabilityList 
                limit={null} 
                showFilters={true}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default Dashboard;

