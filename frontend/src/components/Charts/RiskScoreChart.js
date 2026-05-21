import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './Charts.css';

const RiskScoreChart = ({ data }) => {
  // Check if data is empty or invalid
  if (!data || data.length === 0) {
    return (
      <div className="chart-container">
        <h3>Risk Score Distribution</h3>
        <div className="no-data">
          <p style={{ marginBottom: '10px', fontSize: '16px', fontWeight: '500' }}>
            No risk score data available.
          </p>
          <p style={{ fontSize: '14px', color: '#7f8c8d', lineHeight: '1.6' }}>
            Risk scores are automatically calculated when vulnerabilities are created.
            <br />
            <br />
            <strong>To generate risk scores:</strong>
            <br />
            1. Go to <strong>AI Risk Scoring</strong> page
            <br />
            2. Select a completed scan
            <br />
            3. Click <strong>"Generate Assessment"</strong>
            <br />
            <br />
            This will calculate risk scores for all vulnerabilities in that scan.
          </p>
        </div>
      </div>
    );
  }

  // Transform data for chart
  const chartData = data.map(item => ({
    name: item.vulnerability_title?.substring(0, 30) || `Vuln ${item.id}`,
    riskScore: item.overall_score || 0,
    exploitability: item.exploitability_score || 0,
    impact: item.impact_score || 0,
  }));

  return (
    <div className="chart-container">
      <h3>Risk Score Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 80 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis 
            dataKey="name" 
            angle={-45} 
            textAnchor="end" 
            height={100}
            interval={0}
            tick={{ fontSize: 11 }}
          />
          <YAxis 
            domain={[0, 100]}
            label={{ value: 'Risk Score', angle: -90, position: 'insideLeft' }}
          />
          <Tooltip 
            formatter={(value, name) => [value.toFixed(1), name]}
            labelStyle={{ color: '#2c3e50' }}
          />
          <Legend />
          <Bar dataKey="riskScore" fill="#3498db" name="Overall Risk Score" />
          <Bar dataKey="exploitability" fill="#e67e22" name="Exploitability" />
          <Bar dataKey="impact" fill="#e74c3c" name="Impact" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default RiskScoreChart;

