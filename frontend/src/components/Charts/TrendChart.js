import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './Charts.css';

const TrendChart = ({ data }) => {
  return (
    <div className="chart-container">
      <h3>Vulnerability Trend Over Time</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="date" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="critical" stroke="#e74c3c" name="Critical" />
          <Line type="monotone" dataKey="high" stroke="#e67e22" name="High" />
          <Line type="monotone" dataKey="medium" stroke="#f39c12" name="Medium" />
          <Line type="monotone" dataKey="low" stroke="#3498db" name="Low" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TrendChart;

