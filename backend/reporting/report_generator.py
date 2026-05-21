"""
Report generation utilities for PDF and HTML formats
"""
import os
from datetime import datetime
from django.conf import settings
from django.template.loader import render_to_string
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.pdfgen import canvas
# WeasyPrint is optional for HTML to PDF conversion (not currently used)
from io import BytesIO
import logging

logger = logging.getLogger(__name__)


class VulnerabilityReportGenerator:
    """Generator for vulnerability reports in PDF and HTML formats"""
    
    def __init__(self, scan=None, target=None):
        self.scan = scan
        self.target = target
        self.report_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_pdf_report(self, vulnerabilities, report_name=None):
        """
        Generate PDF report from vulnerabilities
        
        Args:
            vulnerabilities: QuerySet or list of Vulnerability objects
            report_name: Optional custom report name
        
        Returns:
            Tuple of (file_path, file_content)
        """
        if report_name is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_name = f"vulnerability_report_{timestamp}"
        
        file_path = os.path.join(self.report_dir, f"{report_name}.pdf")
        
        # Create PDF document
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a252f'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
        )
        
        # Title
        title = Paragraph("Vulnerability Assessment Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Report metadata
        if self.scan or self.target:
            metadata_data = [
                ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Target:', self.target.name if self.target else 'N/A'],
                ['Target Type:', self.target.target_type if self.target else 'N/A'],
                ['Scan ID:', str(self.scan.id) if self.scan else 'N/A'],
                ['Total Vulnerabilities:', str(len(vulnerabilities))],
            ]
        else:
            # All vulnerabilities report
            unique_scans = set(v.scan.id for v in vulnerabilities if v.scan)
            metadata_data = [
                ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Report Type:', 'All Vulnerabilities Report'],
                ['Total Vulnerabilities:', str(len(vulnerabilities))],
                ['Total Scans:', str(len(unique_scans))],
            ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(metadata_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Summary statistics
        summary_heading = Paragraph("Summary Statistics", heading_style)
        elements.append(summary_heading)
        
        # Calculate summary stats efficiently
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for v in vulnerabilities:
            if v.severity == 'critical':
                critical_count += 1
            elif v.severity == 'high':
                high_count += 1
            elif v.severity == 'medium':
                medium_count += 1
            elif v.severity == 'low':
                low_count += 1
        
        summary_data = [
            ['Severity', 'Count'],
            ['Critical', str(critical_count)],
            ['High', str(high_count)],
            ['Medium', str(medium_count)],
            ['Low', str(low_count)],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#e74c3c')),
            ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#e67e22')),
            ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#f39c12')),
            ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#3498db')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Vulnerability details
        details_heading = Paragraph("Vulnerability Details", heading_style)
        elements.append(details_heading)
        
        # Sort vulnerabilities by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: (severity_order.get(v.severity, 5), -(v.cvss_score or 0)))
        
        for idx, vuln in enumerate(sorted_vulns, 1):
            # Get risk score if available
            risk_score = None
            if hasattr(vuln, 'risk_score') and vuln.risk_score:
                risk_score = vuln.risk_score.overall_score
            
            # Vulnerability header
            vuln_title = f"{idx}. {vuln.title}"
            elements.append(Paragraph(vuln_title, styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Vulnerability details table
            cvss_display = f"{vuln.cvss_score:.1f}" if vuln.cvss_score else 'N/A'
            risk_display = f"{risk_score:.1f}/100" if risk_score else 'N/A'
            
            vuln_data = [
                ['CVE ID:', vuln.cve_id or 'N/A'],
                ['Severity:', vuln.severity.upper()],
                ['CVSS Score:', cvss_display],
                ['AI Risk Score:', risk_display],
                ['Affected Asset:', vuln.location or 'N/A'],
                ['Vulnerability Type:', vuln.vulnerability_type or 'N/A'],
                ['Detected:', vuln.detected_at.strftime('%Y-%m-%d %H:%M:%S')],
            ]
            
            vuln_table = Table(vuln_data, colWidths=[2*inch, 4*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.1*inch))
            
            # Description
            if vuln.description:
                desc_para = Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal'])
                elements.append(desc_para)
                elements.append(Spacer(1, 0.1*inch))
            
            # Remediation steps
            if vuln.remediation_steps:
                elements.append(Paragraph("<b>Remediation Steps:</b>", styles['Normal']))
                for step_idx, step in enumerate(vuln.remediation_steps, 1):
                    step_text = f"{step_idx}. {step}" if isinstance(step, str) else f"{step_idx}. {step.get('step', '')}"
                    elements.append(Paragraph(step_text, styles['Normal']))
            elif vuln.recommendation:
                elements.append(Paragraph("<b>Recommendation:</b>", styles['Normal']))
                elements.append(Paragraph(vuln.recommendation, styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
            
            # Page break for long reports
            if idx % 3 == 0 and idx < len(sorted_vulns):
                elements.append(PageBreak())
        
        # Build PDF
        doc.build(elements)
        
        # Get PDF content
        pdf_content = buffer.getvalue()
        buffer.close()
        
        # Save to file
        with open(file_path, 'wb') as f:
            f.write(pdf_content)
        
        logger.info(f"PDF report generated: {file_path}")
        
        return file_path, pdf_content
    
    def generate_html_report(self, vulnerabilities, report_name=None):
        """
        Generate HTML report from vulnerabilities
        
        Args:
            vulnerabilities: QuerySet or list of Vulnerability objects
            report_name: Optional custom report name
        
        Returns:
            Tuple of (file_path, html_content)
        """
        if report_name is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_name = f"vulnerability_report_{timestamp}"
        
        file_path = os.path.join(self.report_dir, f"{report_name}.html")
        
        # Prepare data for template
        context = {
            'report_name': report_name,
            'generated_at': datetime.now(),
            'target': self.target,
            'scan': self.scan,
            'vulnerabilities': self._prepare_vulnerability_data(vulnerabilities),
            'summary': self._calculate_summary(vulnerabilities),
        }
        
        # Generate HTML
        html_content = render_to_string('reporting/vulnerability_report.html', context)
        
        # Save to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {file_path}")
        
        return file_path, html_content
    
    def _prepare_vulnerability_data(self, vulnerabilities):
        """Prepare vulnerability data for template"""
        data = []
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: (severity_order.get(v.severity, 5), -(v.cvss_score or 0)))
        
        for vuln in sorted_vulns:
            risk_score = None
            if hasattr(vuln, 'risk_score') and vuln.risk_score:
                risk_score = vuln.risk_score.overall_score
            
            data.append({
                'title': vuln.title,
                'cve_id': vuln.cve_id or 'N/A',
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'risk_score': risk_score,
                'location': vuln.location,
                'vulnerability_type': vuln.vulnerability_type,
                'description': vuln.description,
                'remediation_steps': vuln.remediation_steps if vuln.remediation_steps else [vuln.recommendation] if vuln.recommendation else [],
                'detected_at': vuln.detected_at,
            })
        
        return data
    
    def _calculate_summary(self, vulnerabilities):
        """Calculate summary statistics efficiently"""
        total = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for v in vulnerabilities:
            total += 1
            if v.severity == 'critical':
                critical += 1
            elif v.severity == 'high':
                high += 1
            elif v.severity == 'medium':
                medium += 1
            elif v.severity == 'low':
                low += 1
        
        return {
            'total': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
        }

