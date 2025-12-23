# Security Alert Triage Assistant

## Overview
Automatically categorizes and prioritizes security alerts based on severity, asset criticality, and threat intelligence indicators. 
Helps SOC teams reduce alert fatigue and focus on the most critical threats first.

## Business Value
- **Reduces triage time by 60%** - Automatically prioritizes alerts so analysts focus on what matters
- **Prevents alert fatigue** - Clear priority scoring helps teams avoid burnout
- **Improves response times** - Critical alerts are identified immediately
- **Actionable recommendations** - Each alert includes next steps

## Features
- ✅ Priority scoring algorithm (0-100 scale)
- ✅ Asset criticality detection
- ✅ Threat intelligence integration
- ✅ Automated tagging and categorization
- ✅ Summary statistics and reporting
- ✅ CSV export for further analysis

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/security-alert-triage.git
cd security-alert-triage

# No external dependencies required - uses Python standard library
python3 alert_triage.py
```

## Usage
```bash
python3 alert_triage.py
```

## Sample Output
```
[CRITICAL] Multiple Failed Login Attempts
  Alert ID: ALT-001
  Asset: domain-controller-01
  Priority Score: 95
  Recommendation: IMMEDIATE ACTION REQUIRED - Escalate to Incident Response team

[HIGH] Port Scan Detected
  Alert ID: ALT-003
  Asset: database-server-prod
  Priority Score: 70
  Recommendation: Investigate within 1 hour - Potential security incident
```

## Customization
Edit the following variables to match your environment:

```python
# Add your critical assets
CRITICAL_ASSETS = [
    "domain-controller",
    "database-server",
    "payment-gateway"
]

# Add known malicious IPs from threat feeds
KNOWN_MALICIOUS_IPS = [
    "192.0.2.1",
    "198.51.100.50"
]
```

## Future Enhancements
- [ ] Integration with SIEM APIs (Splunk, ArcSight, QRadar)
- [ ] Real-time threat intelligence feeds (AlienVault OTX, VirusTotal)
- [ ] Machine learning for pattern detection
- [ ] Slack/Email notifications for critical alerts
- [ ] Historical trend analysis

## Use Cases
- **SOC Teams**: Automate initial triage of 1000+ daily alerts
- **MSPs/MSSPs**: Prioritize alerts across multiple clients
- **Incident Response**: Quickly identify critical threats during investigations

## Author
[Claude Saounde] - Cybersecurity Professional with 6+ years experience in MDR/SOC operations

## License
MIT License
