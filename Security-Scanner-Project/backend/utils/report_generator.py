"""Report Generator
Compiles security findings into comprehensive reports
"""

from typing import List, Dict
from datetime import datetime

class ReportGenerator:
    """Generates comprehensive security reports"""
    
    SEVERITY_SCORES = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25,
        'SAFE': 0,
    }
    
    @staticmethod
    def generate_report(all_findings: dict, file_info: dict, file_hash: dict) -> dict:
        """
        Generate comprehensive security report
        
        Args:
            all_findings: Dict of findings from all analyzers
            file_info: File metadata
            file_hash: File hash values
            
        Returns:
            Complete security report dict
        """
        # Calculate overall security score
        total_score = 100
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_findings = 0
        
        for analyzer_name, results in all_findings.items():
            if isinstance(results, dict) and 'findings' in results:
                total_findings += len(results['findings'])
                
                # Count severities from findings
                for finding in results['findings']:
                    severity = finding.get('severity', 'LOW')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        total_score -= ReportGenerator._get_severity_penalty(severity)
        
        # Ensure score doesn't go below 0
        security_score = max(0, total_score)
        
        # Determine overall risk level
        risk_level = ReportGenerator._calculate_risk_level(security_score, severity_counts)
        
        # Generate recommendations
        recommendations = ReportGenerator._generate_recommendations(all_findings, severity_counts)
        
        return {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'file_info': file_info,
                'file_hash': file_hash,
            },
            'security_score': security_score,
            'risk_level': risk_level,
            'summary': {
                'total_issues': total_findings,
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
            },
            'findings_by_category': all_findings,
            'recommendations': recommendations,
        }
    
    @staticmethod
    def _get_severity_penalty(severity: str) -> int:
        """Get score penalty for severity level"""
        penalties = {
            'CRITICAL': 20,
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2,
        }
        return penalties.get(severity, 0)
    
    @staticmethod
    def _calculate_risk_level(score: int, severity_counts: dict) -> str:
        """Calculate overall risk level"""
        if severity_counts['CRITICAL'] > 0 or score < 40:
            return 'CRITICAL'
        elif severity_counts['HIGH'] > 0 or score < 60:
            return 'HIGH'
        elif severity_counts['MEDIUM'] > 0 or score < 80:
            return 'MEDIUM'
        elif severity_counts['LOW'] > 0:
            return 'LOW'
        else:
            return 'SAFE'
    
    @staticmethod
    def _generate_recommendations(all_findings: dict, severity_counts: dict) -> list:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Priority recommendations based on severity
        if severity_counts['CRITICAL'] > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'Immediate Action Required',
                'description': f'Found {severity_counts["CRITICAL"]} critical security issue(s). Address these immediately before deployment.',
                'actions': [
                    'Review all API keys and secrets - remove or move to environment variables',
                    'Check cloud storage bucket permissions',
                    'Remove hardcoded credentials'
                ]
            })
        
        if severity_counts['HIGH'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'High Priority Issues',
                'description': f'Found {severity_counts["HIGH"]} high severity issue(s) that should be addressed soon.',
                'actions': [
                    'Replace HTTP with HTTPS for all network calls',
                    'Update deprecated cryptographic algorithms',
                    'Review Android permissions - remove unnecessary ones'
                ]
            })
        
        if severity_counts['MEDIUM'] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Code Quality Improvements',
                'description': f'Found {severity_counts["MEDIUM"]} medium severity issue(s).',
                'actions': [
                    'Remove internal infrastructure references',
                    'Clean up FIXME and HACK comments',
                    'Review debug flags and logging'
                ]
            })
        
        if severity_counts['LOW'] > 0:
            recommendations.append({
                'priority': 'LOW',
                'title': 'Code Cleanup',
                'description': f'Found {severity_counts["LOW"]} low severity issue(s).',
                'actions': [
                    'Remove TODO comments',
                    'Clean up developer emails',
                    'Replace console.log with proper logging'
                ]
            })
        
        if not recommendations:
            recommendations.append({
                'priority': 'SAFE',
                'title': 'No Security Issues Found',
                'description': 'The file appears to be clean. No major security issues detected.',
                'actions': [
                    'Continue following security best practices',
                    'Regular security audits recommended'
                ]
            })
        
        return recommendations
    
    @staticmethod
    def generate_url_report(url: str, findings: dict) -> dict:
        """
        Generate report for URL scans
        
        Args:
            url: Scanned URL
            findings: URL scan findings
            
        Returns:
            URL security report
        """
        security_score = 100
        issues = []
        
        # Analyze URL structure
        if url.startswith('http://'):
            security_score -= 40
            issues.append({
                'severity': 'HIGH',
                'type': 'Insecure Protocol',
                'description': 'URL uses HTTP instead of HTTPS'
            })
        
        # Check for IP address
        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            security_score -= 20
            issues.append({
                'severity': 'MEDIUM',
                'type': 'IP-based URL',
                'description': 'URL uses IP address instead of domain name'
            })
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            security_score -= 30
            issues.append({
                'severity': 'HIGH',
                'type': 'Suspicious TLD',
                'description': 'URL uses a TLD commonly associated with spam/phishing'
            })
        
        risk_level = 'SAFE'
        if security_score < 40:
            risk_level = 'CRITICAL'
        elif security_score < 60:
            risk_level = 'HIGH'
        elif security_score < 80:
            risk_level = 'MEDIUM'
        elif security_score < 100:
            risk_level = 'LOW'
        
        return {
            'url': url,
            'security_score': max(0, security_score),
            'risk_level': risk_level,
            'issues': issues,
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def generate_enhanced_url_report(url: str, enhanced_results: dict, basic_findings: dict) -> dict:
        """
        Generate comprehensive URL report with SSL, Safe Browsing, and URLScan.io data
        
        Args:
            url: Scanned URL
            enhanced_results: Results from EnhancedURLScanner
            basic_findings: Results from basic analyzers
            
        Returns:
            Comprehensive URL security report
        """
        security_score = 100
        issues = []
        checks_performed = enhanced_results.get('checks_performed', [])
        
        # 1. SSL Certificate Analysis
        ssl_info = enhanced_results.get('ssl_certificate', {})
        if ssl_info:
            if ssl_info.get('valid'):
                status = ssl_info.get('status', 'UNKNOWN')
                if status == 'EXPIRED':
                    security_score -= 50
                    issues.append({
                        'severity': 'CRITICAL',
                        'type': 'SSL Certificate Expired',
                        'description': f"Certificate expired on {ssl_info.get('expires', 'unknown date')}",
                        'recommendation': 'Do not visit this site. The SSL certificate has expired.'
                    })
                elif status == 'EXPIRING_SOON':
                    security_score -= 20
                    issues.append({
                        'severity': 'HIGH',
                        'type': 'SSL Certificate Expiring Soon',
                        'description': f"Certificate expires in {ssl_info.get('days_until_expiry', '?')} days",
                        'recommendation': 'Certificate is valid but will expire soon.'
                    })
            else:
                # SSL check failed
                severity = ssl_info.get('severity', 'HIGH')
                if severity == 'CRITICAL':
                    security_score -= 50
                else:
                    security_score -= 30
                
                issues.append({
                    'severity': severity,
                    'type': 'SSL Certificate Error',
                    'description': ssl_info.get('error', 'SSL validation failed'),
                    'recommendation': ssl_info.get('recommendation', 'Avoid visiting this site.')
                })
        
        # 2. Google Safe Browsing
        gsb_info = enhanced_results.get('google_safe_browsing', {})
        if gsb_info.get('enabled'):
            if not gsb_info.get('safe', True):
                # Threats found!
                security_score = 0  # Automatic critical
                threat_types = gsb_info.get('threat_types', [])
                issues.append({
                    'severity': 'CRITICAL',
                    'type': 'Malware/Phishing Detected',
                    'description': f"Google Safe Browsing flagged this URL: {', '.join(threat_types)}",
                    'recommendation': '⚠️ DO NOT VISIT THIS URL! Contains malware, phishing, or harmful content.',
                    'details': gsb_info.get('details', [])
                })
        
        # 3. URLScan.io
        urlscan_info = enhanced_results.get('urlscan_io', {})
        if urlscan_info.get('status') == 'submitted':
            # URL was submitted for scanning
            issues.append({
                'severity': 'INFO',
                'type': 'URLScan.io Submission',
                'description': 'URL submitted to URLScan.io for deep analysis',
                'recommendation': f"View full results at: {urlscan_info.get('result_link', 'N/A')}",
                'scan_id': urlscan_info.get('scan_id')
            })
        
        # 4. Basic Protocol & Domain Checks
        if url.startswith('http://'):
            security_score -= 40
            issues.append({
                'severity': 'HIGH',
                'type': 'Insecure Protocol',
                'description': 'URL uses HTTP instead of HTTPS',
                'recommendation': 'Always use HTTPS for secure communication'
            })
        
        # Check for IP address
        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            security_score -= 20
            issues.append({
                'severity': 'MEDIUM',
                'type': 'IP-based URL',
                'description': 'URL uses IP address instead of domain name',
                'recommendation': 'Legitimate sites typically use domain names, not IP addresses'
            })
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            security_score -= 25
            issues.append({
                'severity': 'HIGH',
                'type': 'Suspicious TLD',
                'description': 'URL uses a top-level domain commonly associated with spam/phishing',
                'recommendation': 'Exercise caution with URLs using free or suspicious TLDs'
            })
        
        # Calculate final risk level
        security_score = max(0, security_score)
        
        if security_score < 20:
            risk_level = 'CRITICAL'
        elif security_score < 40:
            risk_level = 'HIGH'
        elif security_score < 70:
            risk_level = 'MEDIUM'
        elif security_score < 90:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'
        
        # Override risk level if specific critical issues found
        if any(issue.get('severity') == 'CRITICAL' for issue in issues):
            risk_level = 'CRITICAL'
        
        return {
            'url': url,
            'security_score': security_score,
            'risk_level': risk_level,
            'timestamp': enhanced_results.get('timestamp'),
            'checks_performed': checks_performed,
            'ssl_certificate': ssl_info if ssl_info else None,
            'google_safe_browsing': gsb_info if gsb_info.get('enabled') else None,
            'urlscan_io': urlscan_info if urlscan_info.get('enabled') else None,
            'issues': issues,
            'total_issues': len(issues),
            'summary': {
                'critical': len([i for i in issues if i.get('severity') == 'CRITICAL']),
                'high': len([i for i in issues if i.get('severity') == 'HIGH']),
                'medium': len([i for i in issues if i.get('severity') == 'MEDIUM']),
                'low': len([i for i in issues if i.get('severity') == 'LOW']),
            }
        }
