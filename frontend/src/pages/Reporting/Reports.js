import React, { useState, useEffect } from 'react';
import { reportingService } from '../../services/reportingService';
import { scanningService } from '../../services/scanningService';
import './Reporting.css';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [formData, setFormData] = useState({
    scan_id: '',
    target_id: '',
    report_type: 'scan',
    format: 'pdf',
    report_name: '',
  });
  const [isGenerating, setIsGenerating] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    fetchReports();
    fetchScans();
    fetchTargets();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await reportingService.getReports();
      setReports(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setLoading(false);
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

  const fetchTargets = async () => {
    try {
      const response = await scanningService.getTargets();
      setTargets(response.data.results || response.data);
    } catch (error) {
      console.error('Error fetching targets:', error);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear the other ID when one is selected
    if (name === 'scan_id' && value) {
      setFormData(prev => ({ ...prev, target_id: '' }));
    } else if (name === 'target_id' && value) {
      setFormData(prev => ({ ...prev, scan_id: '' }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setIsGenerating(true);

    try {
      const payload = {
        report_type: formData.report_type,
        format: formData.format,
      };

      if (formData.scan_id) {
        payload.scan_id = parseInt(formData.scan_id);
      } else if (formData.target_id) {
        payload.target_id = parseInt(formData.target_id);
      } else {
        setErrorMessage('Please select either a scan or a target');
        setIsGenerating(false);
        return;
      }

      if (formData.report_name) {
        payload.report_name = formData.report_name;
      }

      const response = await reportingService.generateReport(payload);
      setSuccessMessage('Report generated successfully!');
      setShowForm(false);
      setFormData({
        scan_id: '',
        target_id: '',
        report_type: 'scan',
        format: 'pdf',
        report_name: '',
      });
      fetchReports(); // Refresh the list
    } catch (error) {
      console.error('Error generating report:', error);
      setErrorMessage(
        error.response?.data?.error || 
        error.response?.data?.detail || 
        'Failed to generate report. Please check your input and try again.'
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownload = async (reportId) => {
    try {
      const response = await reportingService.downloadReport(reportId);
      // Create a blob and download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report_${reportId}.${reports.find(r => r.id === reportId)?.format || 'pdf'}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('Failed to download report. Please try again.');
    }
  };

  if (loading) {
    return <div>Loading reports...</div>;
  }

  return (
    <div className="reporting-page">
      <div className="page-header">
        <h1>Reports</h1>
        <button 
          className="btn-primary" 
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? 'Cancel' : 'Generate Report'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="form-card">
          <h2>Generate New Report</h2>
          {errorMessage && <p className="error-message">{errorMessage}</p>}
          {successMessage && <p className="success-message">{successMessage}</p>}

          <div className="form-group">
            <label>Select Scan:</label>
            <select
              name="scan_id"
              value={formData.scan_id}
              onChange={handleInputChange}
            >
              <option value="">-- Select a Scan --</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  Scan #{scan.id} - {scan.target_name} ({scan.status})
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>OR Select Target:</label>
            <select
              name="target_id"
              value={formData.target_id}
              onChange={handleInputChange}
            >
              <option value="">-- Select a Target --</option>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.target_type})
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Report Type:</label>
            <select
              name="report_type"
              value={formData.report_type}
              onChange={handleInputChange}
              required
            >
              <option value="scan">Scan Report</option>
              <option value="target">Target Report</option>
              <option value="executive">Executive Summary</option>
              <option value="technical">Technical Report</option>
            </select>
          </div>

          <div className="form-group">
            <label>Format:</label>
            <select
              name="format"
              value={formData.format}
              onChange={handleInputChange}
              required
            >
              <option value="pdf">PDF</option>
              <option value="html">HTML</option>
            </select>
          </div>

          <div className="form-group">
            <label>Report Name (Optional):</label>
            <input
              type="text"
              name="report_name"
              value={formData.report_name}
              onChange={handleInputChange}
              placeholder="Leave empty for auto-generated name"
            />
          </div>

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isGenerating}
          >
            {isGenerating ? 'Generating...' : 'Generate Report'}
          </button>
        </form>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Format</th>
              <th>Generated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {reports.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center' }}>
                  No reports generated yet. Click "Generate Report" to create one.
                </td>
              </tr>
            ) : (
              reports.map((report) => (
                <tr key={report.id}>
                  <td>{report.name}</td>
                  <td>{report.report_type}</td>
                  <td>{report.format.toUpperCase()}</td>
                  <td>{new Date(report.generated_at).toLocaleString()}</td>
                  <td>
                    <button 
                      className="btn-sm btn-success"
                      onClick={() => handleDownload(report.id)}
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Reports;

