# Executive Vulnerability Report Generator

## Overview
Converts technical vulnerability scan data into executive-friendly reports with business impact analysis and risk scoring. Helps bridge the gap between technical security teams and business stakeholders.

## Business Value
- **Enables executive decision-making** - Translates CVE numbers into business risk
- **Speeds up remediation approval** - Clear cost/benefit analysis for patching
- **Improves stakeholder communication** - Non-technical language for board presentations
- **Prioritizes limited resources** - Focus on highest business impact first

## Features
- ✅ Business impact assessment (not just CVSS scores)
- ✅ Cost estimation for potential breaches
- ✅ Prioritized remediation recommendations
- ✅ HTML export for email/presentations
- ✅ Executive summary with overall risk level
- ✅ Timeline and effort estimates

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/exec-vuln-reports.git
cd exec-vuln-reports

# No external dependencies required
python3 vuln_report.py
```

## Usage
```bash
python3 vuln_report.py

# Outputs:
# - executive_report.txt (for printing/sharing)
# - executive_report.html (for email/presentations)
```

## Sample Output

### Executive Summary
```
Overall Risk Level: CRITICAL
Total Vulnerabilities: 5
Critical/High Priority: 3
Systems Affected: 8

Risk Assessment: Immediate action required to prevent potential data breach
```

### Business Impact Example
```
CRITICAL: 2 vulnerabilities
  Business Impact: Could result in data breach, regulatory fines, or business disruption
  Potential Cost: $500K - $5M+ in breach costs
  Recommended Action: Immediate remediation required within 24 hours
```

## Customization

### Add Your Vulnerability Data
Replace `SAMPLE_VULNERABILITIES` with actual scan data from Nessus, Qualys, or other tools:

```python
vulnerabilities = [
    {
        'cve_id': 'CVE-2024-1234',
        'title': 'Your vulnerability title',
        'severity': 'critical',
        'cvss_score': 9.8,
        'affected_systems': ['server1', 'server2'],
        'exploit_available': True,
        'patch_available': True
    }
]
```

### Customize Business Impact
Edit the `BUSINESS_IMPACT` dictionary to match your organization's risk tolerance and cost models.

## Real-World Applications

**For TAMs:**
- Present security posture to customer executives
- Justify security investments to CFO/Board
- Communicate remediation priorities to IT teams

**For MSPs:**
- Create client-facing security reports
- Demonstrate ongoing value to customers
- Drive patch management services

**For Internal Security Teams:**
- Get buy-in for urgent patching
- Justify additional security budget
- Report to audit committees

## Integration Examples

### Parse Nessus CSV
```python
import csv

def load_nessus_scan(filename):
    vulnerabilities = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulnerabilities.append({
                'cve_id': row['CVE'],
                'title': row['Name'],
                'severity': row['Risk'].lower(),
                # ... map other fields
            })
    return vulnerabilities
```

### Parse Qualys XML
```python
import xml.etree.ElementTree as ET

def load_qualys_scan(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    # Parse XML and extract vulnerability data
```

## Future Enhancements
- [ ] Direct integration with Nessus/Qualys APIs
- [ ] Trend analysis (compare current vs previous scans)
- [ ] PowerPoint export for board presentations
- [ ] Email automation for monthly reports
- [ ] ROI calculator for remediation vs breach costs

## Use Cases
1. **Monthly Executive Briefings** - Automated reports for leadership
2. **Board Presentations** - High-level security posture updates
3. **Audit Compliance** - Demonstrate vulnerability management program
4. **Customer Quarterly Reviews** - Show security improvements over time

## Author
[Claude Saounde] - Cybersecurity Professional with 6+ years experience in MDR/SOC operations

## License
MIT License
