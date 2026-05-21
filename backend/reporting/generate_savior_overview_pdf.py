import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="DocTitle", parent=styles["Title"], fontSize=24, textColor=colors.HexColor("#2563eb"), spaceAfter=16))
    styles.add(ParagraphStyle(name="DocH1", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#2563eb"), spaceAfter=12))
    styles.add(ParagraphStyle(name="DocH2", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#0ea5e9"), spaceAfter=8))
    styles.add(ParagraphStyle(name="DocBody", parent=styles["BodyText"], fontSize=11, leading=15, textColor=colors.HexColor("#0f172a"), spaceAfter=8))
    styles.add(ParagraphStyle(name="DocEmphasis", parent=styles["BodyText"], fontSize=11, leading=15, textColor=colors.HexColor("#e74c3c"), spaceAfter=8))
    return styles

def section_title(text, styles):
    return Paragraph(text, styles["DocH1"])

def subheading(text, styles):
    return Paragraph(text, styles["DocH2"])

def bullet_list(items, styles):
    return ListFlowable(
        [ListItem(Paragraph(i, styles["DocBody"])) for i in items],
        bulletType="bullet",
        start="circle",
        leftIndent=18,
        bulletFontName="Helvetica",
        bulletFontSize=10,
        bulletColor=colors.HexColor("#2563eb"),
    )

def generate(output_path):
    os.makedirs(os.path.join(os.path.dirname(output_path)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.9 * inch,
        title="SAVIOR Overview",
        author="SAVIOR",
    )

    styles = build_styles()
    elements = []

    elements.append(Paragraph("SAVIOR — Simple Overview", styles["DocTitle"]))
    elements.append(Paragraph("SAVIOR is an AI-powered vulnerability scanner. It helps teams find security issues across websites, networks, APIs, containers, and code. It shows results in a clean dashboard, explains risks, and sends alerts when something serious appears.", styles["DocBody"]))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["DocBody"]))
    elements.append(Spacer(1, 12))

    elements.append(section_title("What SAVIOR Does", styles))
    elements.append(bullet_list([
        "Scans different targets (web, network, API, containers, and source code).",
        "Calculates AI risk scores to highlight what matters first.",
        "Shows easy-to-read dashboards and creates PDF/HTML reports.",
        "Sends alerts by email (and SMS/webhook if configured).",
        "Stores results safely in MongoDB for history and audits.",
    ], styles))

    elements.append(section_title("Main Features", styles))
    elements.append(subheading("1) Scanning", styles))
    elements.append(bullet_list([
        "Add targets and run scans from the Scanning pages.",
        "Find common issues like SQL injection, XSS, weak passwords, and misconfigurations.",
        "Network checks: open ports, insecure services, and exposure.",
        "API checks: endpoints, auth issues, and insecure inputs.",
        "Container and code checks: simple static checks and configuration problems.",
    ], styles))

    elements.append(subheading("2) AI Risk Scoring", styles))
    elements.append(bullet_list([
        "Each vulnerability can have an AI score (0–100).",
        "Score considers exploitability, impact, and confidence.",
        "Higher score = fix sooner. Helps teams focus on real risk.",
        "Shows risk details (exploitability, impact, confidence) next to each item.",
    ], styles))

    elements.append(subheading("3) OVAL Checks", styles))
    elements.append(bullet_list([
        "OVAL is a standard for checking system vulnerabilities.",
        "Backend supports parsing and evaluating OVAL definitions.",
        "Useful for OS-level or package vulnerabilities.",
    ], styles))

    elements.append(subheading("4) Dashboard", styles))
    elements.append(bullet_list([
        "Key Metrics: totals and severity counts.",
        "Charts: severity breakdown, risk scores, and trends over time.",
        "Vulnerabilities list with filters and quick links.",
        "Compliance Overview: simple score, risk level, and recommendations.",
    ], styles))

    elements.append(subheading("5) Reports", styles))
    elements.append(bullet_list([
        "Create PDF/HTML reports from the Dashboard and Reporting pages.",
        "Reports include summaries, details, and simple steps to fix issues.",
        "Useful for sharing with managers, auditors, or clients.",
    ], styles))

    elements.append(subheading("6) Alerts and Notifications", styles))
    elements.append(bullet_list([
        "Alert rules decide when to send notifications (severity, score, CVE, etc.).",
        "Emails for serious findings; optional SMS/webhook if set up.",
        "Automatic alerts after scans or anomaly detection.",
    ], styles))

    elements.append(subheading("7) Data Storage and Security", styles))
    elements.append(bullet_list([
        "Uses MongoDB to store logs, metadata, reports, and scan results.",
        "Keeps history for audits and trend analysis.",
        "Supports SSL/TLS and role-based access.",
        "Configure secure connection settings in environment or settings file.",
    ], styles))

    elements.append(subheading("8) Roles and Access", styles))
    elements.append(bullet_list([
        "Different roles can access different parts (e.g., SOC Manager, Security Analyst).",
        "Protects sensitive data and controls who can manage alerts and scans.",
    ], styles))

    elements.append(section_title("How To Use It", styles))
    elements.append(bullet_list([
        "Login and open the Dashboard to see current situation.",
        "Go to Scanning → Targets, add a target, then run a scan.",
        "Open Vulnerabilities to review findings and risk scores.",
        "Open AI Risk Scoring to generate or view assessments.",
        "Use Reports to export a PDF/HTML.",
        "Set Alerts so the right people get notified quickly.",
    ], styles))

    elements.append(section_title("Why It Helps", styles))
    elements.append(bullet_list([
        "Saves time by focusing on high-risk items first.",
        "Creates easy reports for management and audits.",
        "Keeps a record of improvements over time.",
        "Fits into existing workflows with alerts and APIs.",
    ], styles))

    elements.append(PageBreak())
    elements.append(section_title("Summary", styles))
    elements.append(Paragraph("SAVIOR is a simple, practical tool that finds vulnerabilities, explains the risk clearly, and helps teams fix issues faster. It is designed to be easy to use, easy to share, and safe to operate.", styles["DocBody"]))

    doc.build(elements)

if __name__ == "__main__":
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    docs_dir = os.path.join(repo_root, "docs")
    output_file = os.path.join(docs_dir, "SAVIOR_Overview.pdf")
    generate(output_file)
