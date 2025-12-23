#!/usr/bin/env python3
"""
Security Alert Triage Assistant
Author: [Claude Saounde]
Description: Automatically categorizes and prioritizes security alerts based on 
             severity, asset criticality, and threat intelligence indicators.
"""

import json
import csv
from datetime import datetime
from collections import defaultdict

# Threat intelligence indicators (simplified)
KNOWN_MALICIOUS_IPS = [
    "192.0.2.1",  # Example malicious IP
    "198.51.100.50",
    "203.0.113.100"
]

CRITICAL_ASSETS = [
    "domain-controller",
    "database-server", 
    "payment-gateway",
    "hr-system"
]

def analyze_alert(alert):
    """
    Analyze a single alert and assign priority score.
    
    Priority scoring:
    - Critical asset: +50 points
    - Known malicious IP: +30 points
    - High severity: +20 points
    - Multiple failed attempts: +15 points
    """
    score = 0
    tags = []
    
    # Check asset criticality
    asset_name = alert.get('asset_name', '').lower()
    if any(critical in asset_name for critical in CRITICAL_ASSETS):
        score += 50
        tags.append("CRITICAL_ASSET")
    
    # Check for known malicious IPs
    source_ip = alert.get('source_ip', '')
    if source_ip in KNOWN_MALICIOUS_IPS:
        score += 30
        tags.append("KNOWN_THREAT")
    
    # Check severity
    severity = alert.get('severity', 'low').lower()
    if severity == 'critical':
        score += 20
        tags.append("HIGH_SEVERITY")
    elif severity == 'high':
        score += 15
    
    # Check for repeated attempts
    event_count = alert.get('event_count', 1)
    if event_count > 10:
        score += 15
        tags.append("REPEATED_ATTEMPTS")
    
    # Determine priority tier
    if score >= 70:
        priority = "CRITICAL"
    elif score >= 40:
        priority = "HIGH"
    elif score >= 20:
        priority = "MEDIUM"
    else:
        priority = "LOW"
    
    return {
        'alert_id': alert.get('alert_id'),
        'timestamp': alert.get('timestamp'),
        'alert_name': alert.get('alert_name'),
        'asset_name': alert.get('asset_name'),
        'source_ip': alert.get('source_ip'),
        'original_severity': alert.get('severity'),
        'priority_score': score,
        'priority_tier': priority,
        'tags': ', '.join(tags) if tags else 'NONE',
        'recommendation': get_recommendation(priority, tags)
    }

def get_recommendation(priority, tags):
    """Provide action recommendation based on priority and tags."""
    if priority == "CRITICAL":
        return "IMMEDIATE ACTION REQUIRED - Escalate to Incident Response team"
    elif priority == "HIGH":
        return "Investigate within 1 hour - Potential security incident"
    elif priority == "MEDIUM":
        return "Review within 4 hours - Monitor for escalation"
    else:
        return "Review during normal triage - Low risk"

def generate_summary_stats(analyzed_alerts):
    """Generate summary statistics from analyzed alerts."""
    priority_counts = defaultdict(int)
    tag_counts = defaultdict(int)
    
    for alert in analyzed_alerts:
        priority_counts[alert['priority_tier']] += 1
        if alert['tags'] != 'NONE':
            for tag in alert['tags'].split(', '):
                tag_counts[tag] += 1
    
    return {
        'total_alerts': len(analyzed_alerts),
        'priority_breakdown': dict(priority_counts),
        'top_tags': dict(sorted(tag_counts.items(), key=lambda x: x[1], reverse=True))
    }

def main():
    """Main function to process alerts."""
    # Sample alert data (in real use, this would come from SIEM/log file)
    sample_alerts = [
        {
            'alert_id': 'ALT-001',
            'timestamp': '2024-12-20 10:15:00',
            'alert_name': 'Multiple Failed Login Attempts',
            'asset_name': 'domain-controller-01',
            'source_ip': '192.0.2.1',
            'severity': 'high',
            'event_count': 25
        },
        {
            'alert_id': 'ALT-002',
            'timestamp': '2024-12-20 10:20:00',
            'alert_name': 'Suspicious Outbound Traffic',
            'asset_name': 'workstation-45',
            'source_ip': '10.0.1.45',
            'severity': 'medium',
            'event_count': 5
        },
        {
            'alert_id': 'ALT-003',
            'timestamp': '2024-12-20 10:25:00',
            'alert_name': 'Port Scan Detected',
            'asset_name': 'database-server-prod',
            'source_ip': '198.51.100.50',
            'severity': 'critical',
            'event_count': 100
        },
        {
            'alert_id': 'ALT-004',
            'timestamp': '2024-12-20 10:30:00',
            'alert_name': 'Failed SSH Login',
            'asset_name': 'web-server-02',
            'source_ip': '203.0.113.100',
            'severity': 'low',
            'event_count': 3
        }
    ]
    
    print("=" * 80)
    print("SECURITY ALERT TRIAGE ASSISTANT")
    print("=" * 80)
    print()
    
    # Analyze all alerts
    analyzed_alerts = []
    for alert in sample_alerts:
        analyzed = analyze_alert(alert)
        analyzed_alerts.append(analyzed)
    
    # Sort by priority score (highest first)
    analyzed_alerts.sort(key=lambda x: x['priority_score'], reverse=True)
    
    # Display results
    print("PRIORITIZED ALERTS:")
    print("-" * 80)
    for alert in analyzed_alerts:
        print(f"[{alert['priority_tier']}] {alert['alert_name']}")
        print(f"  Alert ID: {alert['alert_id']}")
        print(f"  Asset: {alert['asset_name']}")
        print(f"  Source IP: {alert['source_ip']}")
        print(f"  Priority Score: {alert['priority_score']}")
        print(f"  Tags: {alert['tags']}")
        print(f"  Recommendation: {alert['recommendation']}")
        print()
    
    # Display summary statistics
    stats = generate_summary_stats(analyzed_alerts)
    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print(f"Total Alerts Processed: {stats['total_alerts']}")
    print()
    print("Priority Breakdown:")
    for priority, count in sorted(stats['priority_breakdown'].items()):
        print(f"  {priority}: {count}")
    print()
    if stats['top_tags']:
        print("Top Alert Tags:")
        for tag, count in stats['top_tags'].items():
            print(f"  {tag}: {count}")
    
    # Export to CSV
    output_file = 'triaged_alerts.csv'
    with open(output_file, 'w', newline='') as f:
        fieldnames = ['alert_id', 'timestamp', 'alert_name', 'asset_name', 'source_ip',
                     'original_severity', 'priority_tier', 'priority_score', 'tags', 'recommendation']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(analyzed_alerts)
    
    print()
    print(f"Results exported to: {output_file}")
    print("=" * 80)

if __name__ == "__main__":
    main()
