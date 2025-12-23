#!/usr/bin/env python3
"""
Security Health Check Dashboard
Author: [Claude Saounde]
Description: Automated security posture checker that validates security controls
             and generates health scores for client environments.
"""

import json
from datetime import datetime
from collections import defaultdict

class SecurityHealthCheck:
    """Main class for running security health checks."""
    
    def __init__(self, client_name):
        self.client_name = client_name
        self.checks = []
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def add_check(self, category, check_name, status, details="", remediation=""):
        """Add a security check result."""
        self.checks.append({
            'category': category,
            'check_name': check_name,
            'status': status,  # PASS, FAIL, WARNING, INFO
            'details': details,
            'remediation': remediation,
            'timestamp': self.timestamp
        })
    
    def calculate_health_score(self):
        """Calculate overall security health score (0-100)."""
        if not self.checks:
            return 0
        
        total_checks = len(self.checks)
        passed = sum(1 for c in self.checks if c['status'] == 'PASS')
        warnings = sum(1 for c in self.checks if c['status'] == 'WARNING')
        
        # Pass = 100%, Warning = 50%, Fail = 0%
        score = ((passed * 1.0) + (warnings * 0.5)) / total_checks * 100
        return round(score, 1)
    
    def get_category_summary(self):
        """Get summary statistics by category."""
        categories = defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'INFO': 0})
        
        for check in self.checks:
            categories[check['category']][check['status']] += 1
        
        return dict(categories)
    
    def get_failed_checks(self):
        """Get all failed checks for remediation."""
        return [c for c in self.checks if c['status'] == 'FAIL']
    
    def generate_report(self):
        """Generate comprehensive health check report."""
        health_score = self.calculate_health_score()
        category_summary = self.get_category_summary()
        failed_checks = self.get_failed_checks()
        
        # Determine health status
        if health_score >= 90:
            health_status = "EXCELLENT"
            status_color = "GREEN"
        elif health_score >= 75:
            health_status = "GOOD"
            status_color = "YELLOW-GREEN"
        elif health_score >= 60:
            health_status = "FAIR"
            status_color = "YELLOW"
        else:
            health_status = "NEEDS IMPROVEMENT"
            status_color = "RED"
        
        report = []
        report.append("=" * 80)
        report.append(f"SECURITY HEALTH CHECK REPORT - {self.client_name}")
        report.append("=" * 80)
        report.append(f"Scan Date: {self.timestamp}")
        report.append(f"Health Score: {health_score}/100 ({health_status})")
        report.append(f"Total Checks: {len(self.checks)}")
        report.append("")
        
        # Category breakdown
        report.append("CATEGORY BREAKDOWN")
        report.append("-" * 80)
        for category, stats in category_summary.items():
            total = sum(stats.values())
            report.append(f"{category}:")
            report.append(f"  ✓ Passed: {stats['PASS']}/{total}")
            if stats['FAIL'] > 0:
                report.append(f"  ✗ Failed: {stats['FAIL']}/{total}")
            if stats['WARNING'] > 0:
                report.append(f"  ⚠ Warnings: {stats['WARNING']}/{total}")
            report.append("")
        
        # Failed checks requiring immediate attention
        if failed_checks:
            report.append("CRITICAL ISSUES REQUIRING ATTENTION")
            report.append("-" * 80)
            for i, check in enumerate(failed_checks, 1):
                report.append(f"{i}. {check['check_name']} ({check['category']})")
                report.append(f"   Issue: {check['details']}")
                report.append(f"   Remediation: {check['remediation']}")
                report.append("")
        else:
            report.append("✓ No critical issues found!")
            report.append("")
        
        # All checks detail
        report.append("DETAILED CHECK RESULTS")
        report.append("-" * 80)
        current_category = None
        for check in sorted(self.checks, key=lambda x: (x['category'], x['status'])):
            if current_category != check['category']:
                current_category = check['category']
                report.append(f"\n[{current_category}]")
            
            status_symbol = {
                'PASS': '✓',
                'FAIL': '✗',
                'WARNING': '⚠',
                'INFO': 'ℹ'
            }.get(check['status'], '?')
            
            report.append(f"  {status_symbol} {check['check_name']}: {check['status']}")
            if check['details']:
                report.append(f"     Details: {check['details']}")
        
        report.append("")
        report.append("=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        
        if health_score >= 90:
            report.append("Excellent security posture! Continue monitoring and maintain current practices.")
        elif health_score >= 75:
            report.append("Good security posture with minor areas for improvement.")
            report.append(f"Priority: Address {len(failed_checks)} failed checks within 30 days.")
        elif health_score >= 60:
            report.append("Fair security posture requiring attention.")
            report.append(f"Priority: Address {len(failed_checks)} failed checks within 14 days.")
        else:
            report.append("URGENT: Security posture needs immediate improvement.")
            report.append(f"Priority: Address {len(failed_checks)} failed checks within 7 days.")
        
        report.append("=" * 80)
        
        return "\n".join(report)

def run_sample_health_check():
    """Run a sample health check with common security controls."""
    
    health_check = SecurityHealthCheck("Acme Corporation")
    
    # Endpoint Protection Checks
    health_check.add_check(
        "Endpoint Protection",
        "Antivirus Coverage",
        "PASS",
        "250 endpoints with active antivirus protection",
        ""
    )
    
    health_check.add_check(
        "Endpoint Protection",
        "EDR Deployment",
        "FAIL",
        "Only 180/250 endpoints have EDR installed (72%)",
        "Deploy EDR to remaining 70 endpoints"
    )
    
    health_check.add_check(
        "Endpoint Protection",
        "Definition Updates",
        "WARNING",
        "15 endpoints have outdated virus definitions (>7 days old)",
        "Configure automatic updates and verify connectivity"
    )
    
    # Patch Management Checks
    health_check.add_check(
        "Patch Management",
        "Critical OS Patches",
        "FAIL",
        "25 servers missing critical security patches from last 30 days",
        "Schedule emergency patching window for critical systems"
    )
    
    health_check.add_check(
        "Patch Management",
        "Application Patching",
        "WARNING",
        "Web browsers on 40 workstations are 2+ versions behind",
        "Push browser updates via GPO or SCCM"
    )
    
    health_check.add_check(
        "Patch Management",
        "Patch Testing Process",
        "PASS",
        "Formal patch testing process documented and followed",
        ""
    )
    
    # Access Control Checks
    health_check.add_check(
        "Access Control",
        "Multi-Factor Authentication",
        "FAIL",
        "MFA only enabled for 30% of privileged accounts",
        "Enforce MFA for all admin accounts and VPN access"
    )
    
    health_check.add_check(
        "Access Control",
        "Password Policy",
        "PASS",
        "Strong password policy enforced (12+ chars, complexity required)",
        ""
    )
    
    health_check.add_check(
        "Access Control",
        "Privileged Access Review",
        "WARNING",
        "Last privileged access review was 4 months ago (policy: quarterly)",
        "Conduct immediate privileged account audit"
    )
    
    # Network Security Checks
    health_check.add_check(
        "Network Security",
        "Firewall Rules",
        "PASS",
        "Firewall rules reviewed and documented",
        ""
    )
    
    health_check.add_check(
        "Network Security",
        "Network Segmentation",
        "WARNING",
        "Flat network with limited VLAN segmentation",
        "Implement network segmentation for PCI and critical systems"
    )
    
    health_check.add_check(
        "Network Security",
        "VPN Security",
        "PASS",
        "VPN using strong encryption (AES-256)",
        ""
    )
    
    # Backup & Recovery Checks
    health_check.add_check(
        "Backup & Recovery",
        "Backup Coverage",
        "PASS",
        "All critical systems backed up daily",
        ""
    )
    
    health_check.add_check(
        "Backup & Recovery",
        "Backup Testing",
        "FAIL",
        "Last backup restoration test was 6 months ago (policy: quarterly)",
        "Schedule immediate backup restoration test"
    )
    
    health_check.add_check(
        "Backup & Recovery",
        "Offsite Storage",
        "PASS",
        "Backups replicated to offsite location (cloud)",
        ""
    )
    
    # Monitoring & Logging Checks
    health_check.add_check(
        "Monitoring & Logging",
        "SIEM Coverage",
        "PASS",
        "Critical systems sending logs to SIEM",
        ""
    )
    
    health_check.add_check(
        "Monitoring & Logging",
        "Log Retention",
        "WARNING",
        "Log retention is 30 days (compliance requires 90 days)",
        "Increase log retention to 90 days for compliance"
    )
    
    health_check.add_check(
        "Monitoring & Logging",
        "Alert Response SLA",
        "PASS",
        "Critical alerts responded to within 1 hour (SLA: 2 hours)",
        ""
    )
    
    # Compliance Checks
    health_check.add_check(
        "Compliance",
        "Security Awareness Training",
        "FAIL",
        "Only 65% of employees completed annual security training",
        "Send reminders and set deadline for remaining 35%"
    )
    
    health_check.add_check(
        "Compliance",
        "Incident Response Plan",
        "PASS",
        "IR plan documented and tested in last 6 months",
        ""
    )
    
    health_check.add_check(
        "Compliance",
        "Vulnerability Scanning",
        "PASS",
        "Monthly vulnerability scans conducted and tracked",
        ""
    )
    
    return health_check

def main():
    """Main function to run health check and generate report."""
    print("Running Security Health Check...")
    print()
    
    # Run sample health check
    health_check = run_sample_health_check()
    
    # Generate and display report
    report = health_check.generate_report()
    print(report)
    
    # Export to file
    filename = f"security_health_check_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, 'w') as f:
        f.write(report)
    
    # Export to JSON for programmatic access
    json_filename = f"security_health_check_{datetime.now().strftime('%Y%m%d')}.json"
    with open(json_filename, 'w') as f:
        json.dump({
            'client_name': health_check.client_name,
            'timestamp': health_check.timestamp,
            'health_score': health_check.calculate_health_score(),
            'checks': health_check.checks,
            'category_summary': health_check.get_category_summary()
        }, f, indent=2)
    
    print()
    print(f"Reports saved:")
    print(f"  - {filename} (text report)")
    print(f"  - {json_filename} (JSON data)")

if __name__ == "__main__":
    main()
