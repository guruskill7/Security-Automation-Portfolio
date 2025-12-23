#!/usr/bin/env python3
"""
Executive Vulnerability Report Generator
Author: [Claude Saounde]
Description: Converts technical vulnerability scan data into executive-friendly 
             reports with business impact analysis and risk scoring.
"""

import json
from datetime import datetime
from collections import defaultdict

# Business impact mapping
BUSINESS_IMPACT = {
    'critical': {
        'risk_level': 'CRITICAL',
        'business_impact': 'Could result in data breach, regulatory fines, or business disruption',
        'recommended_action': 'Immediate remediation required within 24 hours',
        'potential_cost': '$500K - $5M+ in breach costs'
    },
    'high': {
        'risk_level': 'HIGH',
        'business_impact': 'Could lead to unauthorized access or service degradation',
        'recommended_action': 'Remediate within 7 days',
        'potential_cost': '$100K - $500K in potential impact'
    },
    'medium': {
        'risk_level': 'MEDIUM',
        'business_impact': 'May increase attack surface or enable lateral movement',
        'recommended_action': 'Remediate within 30 days',
        'potential_cost': '$10K - $100K in potential impact'
    },
    'low': {
        'risk_level': 'LOW',
        'business_impact': 'Minimal immediate risk, may be exploited in combination with other vulnerabilities',
        'recommended_action': 'Remediate during next maintenance window',
        'potential_cost': '<$10K in potential impact'
    }
}

# Sample vulnerability data
SAMPLE_VULNERABILITIES = [
    {
        'cve_id': 'CVE-2024-1234',
        'title': 'Remote Code Execution in Web Server',
        'severity': 'critical',
        'cvss_score': 9.8,
        'affected_systems': ['web-server-01', 'web-server-02', 'api-gateway-01'],
        'exploit_available': True,
        'patch_available': True,
        'category': 'Remote Code Execution'
    },
    {
        'cve_id': 'CVE-2024-5678',
        'title': 'SQL Injection in Database Layer',
        'severity': 'critical',
        'cvss_score': 9.1,
        'affected_systems': ['database-server-prod'],
        'exploit_available': True,
        'patch_available': True,
        'category': 'Injection Attack'
    },
    {
        'cve_id': 'CVE-2024-9012',
        'title': 'Privilege Escalation in Operating System',
        'severity': 'high',
        'cvss_score': 7.8,
        'affected_systems': ['app-server-01', 'app-server-02', 'app-server-03'],
        'exploit_available': False,
        'patch_available': True,
        'category': 'Privilege Escalation'
    },
    {
        'cve_id': 'CVE-2024-3456',
        'title': 'Information Disclosure in API',
        'severity': 'medium',
        'cvss_score': 5.3,
        'affected_systems': ['api-gateway-01', 'api-gateway-02'],
        'exploit_available': False,
        'patch_available': True,
        'category': 'Information Disclosure'
    },
    {
        'cve_id': 'CVE-2024-7890',
        'title': 'Weak Encryption Algorithm',
        'severity': 'low',
        'cvss_score': 3.7,
        'affected_systems': ['legacy-system-01'],
        'exploit_available': False,
        'patch_available': False,
        'category': 'Cryptographic Issue'
    }
]

def generate_executive_summary(vulnerabilities):
    """Generate high-level executive summary."""
    severity_counts = defaultdict(int)
    total_systems = set()
    exploitable = 0
    
    for vuln in vulnerabilities:
        severity_counts[vuln['severity']] += 1
        total_systems.update(vuln['affected_systems'])
        if vuln['exploit_available']:
            exploitable += 1
    
    critical_high = severity_counts['critical'] + severity_counts['high']
    
    # Risk assessment
    if severity_counts['critical'] > 0:
        overall_risk = "CRITICAL"
        risk_summary = "Immediate action required to prevent potential data breach"
    elif severity_counts['high'] > 3:
        overall_risk = "HIGH"
        risk_summary = "Significant vulnerabilities require prompt attention"
    elif severity_counts['high'] > 0:
        overall_risk = "MEDIUM-HIGH"
        risk_summary = "Multiple vulnerabilities need remediation within 7 days"
    else:
        overall_risk = "MEDIUM"
        risk_summary = "Routine maintenance required"
    
    return {
        'scan_date': datetime.now().strftime('%Y-%m-%d'),
        'total_vulnerabilities': len(vulnerabilities),
        'critical_high_count': critical_high,
        'affected_systems': len(total_systems),
        'exploitable_vulns': exploitable,
        'overall_risk': overall_risk,
        'risk_summary': risk_summary,
        'severity_breakdown': dict(severity_counts)
    }

def generate_business_recommendations(vulnerabilities):
    """Generate prioritized business recommendations."""
    recommendations = []
    
    # Group by severity
    by_severity = defaultdict(list)
    for vuln in vulnerabilities:
        by_severity[vuln['severity']].append(vuln)
    
    # Critical vulnerabilities
    if by_severity['critical']:
        recommendations.append({
            'priority': 1,
            'action': f"IMMEDIATE: Patch {len(by_severity['critical'])} critical vulnerabilities",
            'business_justification': 'These vulnerabilities could lead to complete system compromise, data breach, and potential regulatory fines',
            'timeline': '24 hours',
            'estimated_effort': f"{len(by_severity['critical']) * 2} hours"
        })
    
    # High vulnerabilities
    if by_severity['high']:
        recommendations.append({
            'priority': 2,
            'action': f"URGENT: Address {len(by_severity['high'])} high-severity vulnerabilities",
            'business_justification': 'Could result in unauthorized access and service disruption',
            'timeline': '7 days',
            'estimated_effort': f"{len(by_severity['high']) * 1.5} hours"
        })
    
    # Medium vulnerabilities
    if by_severity['medium']:
        recommendations.append({
            'priority': 3,
            'action': f"PLANNED: Remediate {len(by_severity['medium'])} medium-severity vulnerabilities",
            'business_justification': 'Reduces overall attack surface and prevents potential exploitation chains',
            'timeline': '30 days',
            'estimated_effort': f"{len(by_severity['medium'])} hours"
        })
    
    return recommendations

def format_executive_report(summary, vulnerabilities, recommendations):
    """Format the complete executive report."""
    report = []
    
    # Header
    report.append("=" * 80)
    report.append("EXECUTIVE VULNERABILITY ASSESSMENT REPORT")
    report.append("=" * 80)
    report.append(f"Report Date: {summary['scan_date']}")
    report.append(f"Overall Risk Level: {summary['overall_risk']}")
    report.append("")
    
    # Executive Summary
    report.append("EXECUTIVE SUMMARY")
    report.append("-" * 80)
    report.append(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}")
    report.append(f"Critical/High Priority: {summary['critical_high_count']}")
    report.append(f"Affected Systems: {summary['affected_systems']}")
    report.append(f"Actively Exploited: {summary['exploitable_vulns']}")
    report.append("")
    report.append(f"Risk Assessment: {summary['risk_summary']}")
    report.append("")
    
    # Severity Breakdown
    report.append("RISK BREAKDOWN")
    report.append("-" * 80)
    for severity in ['critical', 'high', 'medium', 'low']:
        count = summary['severity_breakdown'].get(severity, 0)
        if count > 0:
            impact = BUSINESS_IMPACT[severity]
            report.append(f"{impact['risk_level']}: {count} vulnerabilities")
            report.append(f"  Business Impact: {impact['business_impact']}")
            report.append(f"  Potential Cost: {impact['potential_cost']}")
            report.append("")
    
    # Top Priority Vulnerabilities
    report.append("TOP PRIORITY VULNERABILITIES")
    report.append("-" * 80)
    critical_high = [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]
    critical_high.sort(key=lambda x: x['cvss_score'], reverse=True)
    
    for i, vuln in enumerate(critical_high[:5], 1):
        report.append(f"{i}. {vuln['title']}")
        report.append(f"   Severity: {vuln['severity'].upper()} (CVSS {vuln['cvss_score']})")
        report.append(f"   Affected Systems: {len(vuln['affected_systems'])} system(s)")
        report.append(f"   Exploit Available: {'YES - Active threat' if vuln['exploit_available'] else 'No'}")
        report.append(f"   Patch Available: {'YES' if vuln['patch_available'] else 'NO'}")
        impact = BUSINESS_IMPACT[vuln['severity']]
        report.append(f"   Business Impact: {impact['business_impact']}")
        report.append(f"   Recommended Action: {impact['recommended_action']}")
        report.append("")
    
    # Recommendations
    report.append("PRIORITIZED RECOMMENDATIONS")
    report.append("-" * 80)
    for rec in recommendations:
        report.append(f"Priority {rec['priority']}: {rec['action']}")
        report.append(f"  Why: {rec['business_justification']}")
        report.append(f"  Timeline: {rec['timeline']}")
        report.append(f"  Estimated Effort: {rec['estimated_effort']}")
        report.append("")
    
    # Next Steps
    report.append("NEXT STEPS")
    report.append("-" * 80)
    report.append("1. Schedule emergency patching for critical vulnerabilities (within 24 hours)")
    report.append("2. Review and approve remediation timeline with IT operations")
    report.append("3. Allocate resources for vulnerability remediation")
    report.append("4. Schedule follow-up scan in 7 days to verify remediation")
    report.append("5. Implement continuous vulnerability monitoring")
    report.append("")
    
    report.append("=" * 80)
    report.append("For detailed technical information, please refer to the full vulnerability scan report.")
    report.append("=" * 80)
    
    return "\n".join(report)

def export_to_html(summary, vulnerabilities, recommendations):
    """Export report as HTML for email/presentation."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #1F4E78; color: white; padding: 20px; }}
            .critical {{ color: #D32F2F; font-weight: bold; }}
            .high {{ color: #F57C00; font-weight: bold; }}
            .medium {{ color: #FBC02D; font-weight: bold; }}
            .summary {{ background-color: #F5F5F5; padding: 15px; margin: 20px 0; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #1F4E78; color: white; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Executive Vulnerability Assessment Report</h1>
            <p>Report Date: {summary['scan_date']}</p>
        </div>
        
        <div class="summary">
            <h2>Overall Risk: <span class="{summary['overall_risk'].lower()}">{summary['overall_risk']}</span></h2>
            <p><strong>Total Vulnerabilities:</strong> {summary['total_vulnerabilities']}</p>
            <p><strong>Critical/High Priority:</strong> {summary['critical_high_count']}</p>
            <p><strong>Systems Affected:</strong> {summary['affected_systems']}</p>
        </div>
        
        <h2>Risk Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Business Impact</th>
                <th>Potential Cost</th>
            </tr>
    """
    
    for severity in ['critical', 'high', 'medium', 'low']:
        count = summary['severity_breakdown'].get(severity, 0)
        if count > 0:
            impact = BUSINESS_IMPACT[severity]
            html += f"""
            <tr>
                <td class="{severity}">{impact['risk_level']}</td>
                <td>{count}</td>
                <td>{impact['business_impact']}</td>
                <td>{impact['potential_cost']}</td>
            </tr>
            """
    
    html += """
        </table>
        
        <h2>Recommendations</h2>
        <ol>
    """
    
    for rec in recommendations:
        html += f"""
            <li>
                <strong>{rec['action']}</strong><br>
                Timeline: {rec['timeline']} | Effort: {rec['estimated_effort']}<br>
                {rec['business_justification']}
            </li>
        """
    
    html += """
        </ol>
    </body>
    </html>
    """
    
    return html

def main():
    """Main function to generate report."""
    print("Generating Executive Vulnerability Report...")
    print()
    
    # Generate report components
    summary = generate_executive_summary(SAMPLE_VULNERABILITIES)
    recommendations = generate_business_recommendations(SAMPLE_VULNERABILITIES)
    
    # Format and display text report
    report = format_executive_report(summary, SAMPLE_VULNERABILITIES, recommendations)
    print(report)
    
    # Export reports
    with open('executive_report.txt', 'w') as f:
        f.write(report)
    
    html_report = export_to_html(summary, SAMPLE_VULNERABILITIES, recommendations)
    with open('executive_report.html', 'w') as f:
        f.write(html_report)
    
    print()
    print("Reports generated:")
    print("  - executive_report.txt (text version)")
    print("  - executive_report.html (HTML version for email)")

if __name__ == "__main__":
    main()
