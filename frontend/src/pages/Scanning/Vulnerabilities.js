import React from 'react';
import { useNavigate } from 'react-router-dom';
import VulnerabilityList from '../../components/VulnerabilityList/VulnerabilityList';
import './Scanning.css';

const Vulnerabilities = () => {
  const navigate = useNavigate();

  const handleVulnerabilitySelect = (vulnerability) => {
    navigate(`/vulnerabilities/${vulnerability.id}`);
  };

  return (
    <div className="scanning-page">
      <div className="page-header">
        <h1>Vulnerabilities</h1>
      </div>
      <VulnerabilityList onVulnerabilitySelect={handleVulnerabilitySelect} />
    </div>
  );
};

export default Vulnerabilities;

