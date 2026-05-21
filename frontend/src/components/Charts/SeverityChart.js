import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, LabelList } from 'recharts';
import './Charts.css';

const SeverityChart = ({ data }) => {
  const severityData = [
    { name: 'Critical', value: data.critical || 0, color: '#e74c3c' },
    { name: 'High', value: data.high || 0, color: '#e67e22' },
    { name: 'Medium', value: data.medium || 0, color: '#f39c12' },
    { name: 'Low', value: data.low || 0, color: '#3498db' },
    { name: 'Info', value: data.info || 0, color: '#95a5a6' },
  ];

  // Custom label function that positions labels better for small segments
  const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) => {
    const RADIAN = Math.PI / 180;
    // Use outer radius + offset for better positioning of labels outside the pie
    const radius = outerRadius + 20;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);
    
    // Only show label if percentage is greater than 1% to avoid clutter on very small segments
    if (percent < 0.01) {
      return null;
    }

    // Determine text anchor based on position
    const textAnchor = x > cx ? 'start' : 'end';
    
    return (
      <text
        x={x}
        y={y}
        fill="#e5e7eb"
        textAnchor={textAnchor}
        dominantBaseline="central"
        fontSize={11}
        fontWeight="600"
        style={{ 
          textShadow: '0 0 3px rgba(255,255,255,0.8)',
          pointerEvents: 'none'
        }}
      >
        {`${name}: ${(percent * 100).toFixed(0)}%`}
      </text>
    );
  };

  return (
    <div className="chart-container">
      <h3>Vulnerability Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={severityData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={renderCustomLabel}
            outerRadius={100}
            innerRadius={0}
            fill="#8884d8"
            dataKey="value"
            paddingAngle={1}
          >
            {severityData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            formatter={(value, name) => [`${value} (${((value / severityData.reduce((sum, item) => sum + item.value, 0)) * 100).toFixed(1)}%)`, name]}
          />
          <Legend 
            verticalAlign="bottom" 
            height={36}
            formatter={(value, entry) => {
              const total = severityData.reduce((sum, item) => sum + item.value, 0);
              const itemValue = severityData.find(item => item.name === value)?.value || 0;
              const percentage = total > 0 ? ((itemValue / total) * 100).toFixed(0) : 0;
              return `${value}: ${percentage}%`;
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityChart;

