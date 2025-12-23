# Security Health Check Dashboard

## Overview
Automated security posture checker that validates security controls across multiple systems and generates health scores. 
Helps TAMs and security teams proactively identify issues before they become incidents.

## Business Value
- **Proactive client management** - Identify issues before customers notice
- **Quantifiable security posture** - Health score (0-100) shows progress over time
- **Automated reporting** - Reduce manual audit work by 80%
- **Customer confidence** - Regular health checks demonstrate ongoing value

## Features
- ✅ Overall security health score (0-100)
- ✅ Category-based assessment (Endpoint, Network, Access Control, etc.)
- ✅ Failed check identification with remediation steps
- ✅ Trend tracking (compare month-over-month)
- ✅ JSON export for dashboards/integrations
- ✅ Customizable check framework

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/security-health-check.git
cd security-health-check

# No external dependencies required
python3 health_check.py
```

## Usage
```bash
python3 health_check.py

# Outputs:
# - security_health_check_YYYYMMDD.txt (detailed report)
# - security_health_check_YYYYMMDD.json (structured data)
```

## Sample Output

### Health Score
```
SECURITY HEALTH CHECK REPORT - Acme Corporation
Scan Date: 2024-12-20 14:30:00
Health Score: 72.5/100 (GOOD)
Total Checks: 20
```

### Category Breakdown
```
Endpoint Protection:
  ✓ Passed: 1/3
  ✗ Failed: 1/3
  ⚠ Warnings: 1/3

Patch Management:
  ✓ Passed: 1/3
  ✗ Failed: 1/3
  ⚠ Warnings: 1/3
```

### Critical Issues
```
1. EDR Deployment (Endpoint Protection)
   Issue: Only 180/250 endpoints have EDR installed (72%)
   Remediation: Deploy EDR to remaining 70 endpoints

2. Critical OS Patches (Patch Management)
   Issue: 25 servers missing critical security patches
   Remediation: Schedule emergency patching window
```

## Customization

### Add Your Own Security Checks

```python
health_check = SecurityHealthCheck("Your Company")

# Add a check
health_check.add_check(
    category="Endpoint Protection",
    check_name="Antivirus Coverage",
    status="PASS",  # PASS, FAIL, WARNING, INFO
    details="250/250 endpoints protected",
    remediation=""  # Only needed for FAIL/WARNING
)
```

### Create Custom Check Categories

Common categories:
- Endpoint Protection
- Patch Management
- Access Control
- Network Security
- Backup & Recovery
- Monitoring & Logging
- Compliance
- Cloud Security
- Application Security
- Physical Security

### Integrate with Your Tools

**Check Active Directory:**
```python
import ldap

def check_mfa_status():
    # Query AD for MFA enrollment
    # Add check result
    health_check.add_check(...)
```

**Check Cloud Resources:**
```python
import boto3

def check_s3_encryption():
    # Query AWS for unencrypted S3 buckets
    # Add check result
    health_check.add_check(...)
```

**Check Vulnerability Scanners:**
```python
def check_critical_vulns():
    # Query Nessus/Qualys API
    # Count critical vulns
    health_check.add_check(...)
```

## Real-World Applications

**For TAMs:**
- Run monthly health checks for all 250+ clients
- Proactively identify issues before quarterly business reviews
- Show security improvement trends over time
- Justify renewals with concrete health score improvements

**For MSPs:**
- Automated client security audits
- Standardized reporting across all clients
- Track SLA compliance (patch levels, backup success, etc.)
- Identify cross-client trends and issues

**For Internal Security Teams:**
- Continuous control monitoring
- Compliance validation (SOC 2, ISO 27001, PCI-DSS)
- Executive reporting with quantifiable metrics
- Track remediation progress

## Integration Examples

### Monthly Automated Report
```python
import schedule

def monthly_health_check():
    for client in all_clients:
        health_check = SecurityHealthCheck(client.name)
        # Run checks
        # Email report to client
        
schedule.every().month.do(monthly_health_check)
```

### Dashboard Integration
```python
import requests

# Send health score to dashboard
response = requests.post('https://dashboard.example.com/api/metrics', json={
    'client': 'Acme Corp',
    'health_score': health_check.calculate_health_score(),
    'timestamp': datetime.now()
})
```

### Slack Notifications for Failed Checks
```python
def send_slack_alert(failed_checks):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK"
    message = f"⚠️ {len(failed_checks)} security checks failed!"
    requests.post(webhook_url, json={'text': message})
```

## Scoring Methodology

Health score calculation:
- **PASS** = 100% (1.0 weight)
- **WARNING** = 50% (0.5 weight)
- **FAIL** = 0% (0.0 weight)
- **INFO** = Not counted in score

Example:
- 10 PASS + 5 WARNING + 5 FAIL = (10 + 2.5) / 20 = 62.5%

## Future Enhancements
- [ ] API integrations (Active Directory, AWS, Azure, Nessus)
- [ ] Historical trending (track health score over time)
- [ ] Automated remediation workflows
- [ ] Slack/Teams notifications
- [ ] Multi-tenant dashboard
- [ ] Compliance framework mapping (NIST, CIS, PCI-DSS)

## Use Cases

1. **Monthly Client Reviews** - Run before QBRs to show progress
2. **New Client Onboarding** - Baseline security posture assessment
3. **Compliance Audits** - Demonstrate control effectiveness
4. **Executive Reporting** - Simple health score for board presentations
5. **Remediation Tracking** - Before/after comparisons

## Pro Tips

**For TAM Work:**
- Run health checks on the 1st of each month
- Track score trends to show value during renewals
- Use failed checks as upsell opportunities (EDR, MFA, etc.)
- Share reports in QBRs to demonstrate proactive management

## Author
[Claude Saounde] - Cybersecurity Professional with 6+ years experience in MDR/SOC operations

## License
MIT License
