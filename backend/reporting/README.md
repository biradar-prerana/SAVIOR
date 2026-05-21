# Reporting Module

This module provides automated vulnerability report generation in PDF and HTML formats.

## Features

- **PDF Reports**: Professional PDF reports with detailed vulnerability information
- **HTML Reports**: Interactive HTML reports with modern styling
- **Automated Generation**: Generate reports from scans or targets
- **Comprehensive Data**: Includes CVE ID, severity, AI risk scores, affected assets, and remediation steps
- **Summary Statistics**: Visual summary of vulnerability counts by severity

## Report Contents

Each report includes:

1. **Report Metadata**
   - Generation timestamp
   - Target information
   - Scan ID
   - Total vulnerability count

2. **Summary Statistics**
   - Total vulnerabilities
   - Count by severity (Critical, High, Medium, Low)

3. **Vulnerability Details** (for each vulnerability):
   - **CVE ID**: Common Vulnerabilities and Exposures identifier
   - **Severity**: Critical, High, Medium, Low, or Informational
   - **CVSS Score**: Common Vulnerability Scoring System score
   - **AI Risk Score**: AI-generated risk score (0-100)
   - **Affected Asset**: Location/URL of the vulnerability
   - **Vulnerability Type**: Type of vulnerability (e.g., SQL Injection, XSS)
   - **Description**: Detailed description of the vulnerability
   - **Remediation Steps**: Step-by-step remediation instructions
   - **Detection Date**: When the vulnerability was detected

## Usage

### Generate Report via API

#### Generate PDF Report

```bash
POST /api/reporting/reports/generate/
{
    "scan_id": 123,
    "report_type": "scan",
    "format": "pdf",
    "report_name": "Vulnerability_Report_2024"
}
```

#### Generate HTML Report

```bash
POST /api/reporting/reports/generate/
{
    "scan_id": 123,
    "report_type": "scan",
    "format": "html",
    "report_name": "Vulnerability_Report_2024"
}
```

#### Generate Report from Target

```bash
POST /api/reporting/reports/generate/
{
    "target_id": 456,
    "report_type": "target",
    "format": "pdf"
}
```

### Download Report

```bash
GET /api/reporting/reports/{id}/download/
```

This returns the report file (PDF or HTML) for download.

## Report Formats

### PDF Format
- Professional layout with tables and structured sections
- Color-coded severity indicators
- Print-ready format
- Generated using ReportLab

### HTML Format
- Modern, responsive design
- Interactive and easy to navigate
- Color-coded severity badges
- Suitable for web viewing and email
- Generated using Django templates and WeasyPrint

## Report Structure

1. **Header**: Report title and generation date
2. **Metadata Section**: Target and scan information
3. **Summary Section**: Visual summary cards with vulnerability counts
4. **Vulnerability Details**: Detailed information for each vulnerability
   - Sorted by severity (Critical → High → Medium → Low)
   - Includes all required fields (CVE ID, severity, AI risk score, etc.)
   - Remediation steps clearly listed

## Example Report Data

```json
{
    "name": "Vulnerability_Report_20240115",
    "report_type": "scan",
    "format": "pdf",
    "scan": 123,
    "target": 456,
    "file_path": "/media/reports/vulnerability_report_20240115_143022.pdf",
    "report_data": {
        "total_vulnerabilities": 25,
        "critical_count": 3,
        "high_count": 8,
        "medium_count": 10,
        "low_count": 4
    }
}
```

## File Storage

Reports are stored in:
- `MEDIA_ROOT/reports/` directory
- Filenames include timestamp for uniqueness
- Files are accessible via the download endpoint

## Customization

### Report Templates

You can customize report appearance by:
1. Modifying the HTML template: `reporting/templates/reporting/vulnerability_report.html`
2. Adjusting PDF styles in `report_generator.py`
3. Creating custom report templates via the ReportTemplate model

### Report Types

- **scan**: Report for a specific scan
- **target**: Report for a target (uses latest scan)
- **executive**: Executive summary report
- **technical**: Detailed technical report

## Best Practices

1. **Regular Reports**: Schedule regular report generation for ongoing monitoring
2. **Naming Convention**: Use descriptive report names with dates
3. **Storage Management**: Periodically clean up old reports
4. **Access Control**: Ensure proper permissions for report generation
5. **Review Reports**: Regularly review generated reports for accuracy

## API Endpoints

- `POST /api/reporting/reports/generate/` - Generate new report
- `GET /api/reporting/reports/` - List all reports
- `GET /api/reporting/reports/{id}/` - Get report details
- `GET /api/reporting/reports/{id}/download/` - Download report file
- `DELETE /api/reporting/reports/{id}/` - Delete report

## Dependencies

- **reportlab**: PDF generation
- **weasyprint**: HTML to PDF conversion (optional)
- **jinja2**: Template rendering

## Troubleshooting

### Report Generation Fails

1. Check that vulnerabilities exist for the scan/target
2. Verify MEDIA_ROOT directory exists and is writable
3. Check file permissions for report storage directory

### PDF Generation Issues

1. Ensure ReportLab is properly installed
2. Check for font issues (default fonts should work)
3. Verify sufficient disk space

### HTML Template Not Found

1. Ensure template is in `reporting/templates/reporting/`
2. Check Django TEMPLATES configuration
3. Verify APP_DIRS is True in TEMPLATES settings

