#!/usr/bin/env python3
"""
SafetyScan Report Generator
Generates comprehensive, organized security reports from SAST and DAST scan results
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse


class ReportGenerator:
    def __init__(self, report_dir: str, project_name: str):
        self.report_dir = Path(report_dir)
        self.project_name = project_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # File paths
        self.semgrep_json = self.report_dir / "semgrep.json"
        self.zap_json = self.report_dir / "zap-report.json"
        self.output_html = self.report_dir / "comprehensive-security-report.html"
        self.output_md = self.report_dir / "comprehensive-security-report.md"
        
        # Data containers
        self.sast_data = None
        self.dast_data = None
        self.stats = {
            'sast': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
            'dast': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
        }

    def load_data(self) -> bool:
        """Load SAST and DAST data from JSON files"""
        success = True
        
        # Load Semgrep data
        if self.semgrep_json.exists():
            try:
                with open(self.semgrep_json, 'r', encoding='utf-8') as f:
                    self.sast_data = json.load(f)
                print(f"✓ Loaded SAST data from {self.semgrep_json}")
            except Exception as e:
                print(f"✗ Error loading SAST data: {e}")
                self.sast_data = None
        else:
            print(f"⚠ SAST data not found at {self.semgrep_json}")
        
        # Load ZAP data
        if self.zap_json.exists():
            try:
                with open(self.zap_json, 'r', encoding='utf-8') as f:
                    self.dast_data = json.load(f)
                print(f"✓ Loaded DAST data from {self.zap_json}")
            except Exception as e:
                print(f"✗ Error loading DAST data: {e}")
                self.dast_data = None
        else:
            print(f"⚠ DAST data not found at {self.zap_json}")
        
        # Return true if at least one dataset was loaded
        return self.sast_data is not None or self.dast_data is not None

    def parse_semgrep_data(self) -> Dict[str, List[Dict]]:
        """Parse and categorize Semgrep findings"""
        findings = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        if not self.sast_data or 'results' not in self.sast_data:
            return findings
        
        for result in self.sast_data.get('results', []):
            severity = result.get('extra', {}).get('severity', 'INFO').upper()
            
            # Map Semgrep severity to our levels
            severity_map = {
                'ERROR': 'critical',
                'WARNING': 'high',
                'INFO': 'low'
            }
            mapped_severity = severity_map.get(severity, 'info')
            
            finding = {
                'rule_id': result.get('check_id', 'Unknown'),
                'message': result.get('extra', {}).get('message', 'No description'),
                'file': result.get('path', 'Unknown'),
                'line': result.get('start', {}).get('line', 0),
                'code': result.get('extra', {}).get('lines', ''),
                'severity': severity,
                'category': result.get('extra', {}).get('metadata', {}).get('category', 'general'),
                'cwe': result.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': result.get('extra', {}).get('metadata', {}).get('owasp', [])
            }
            
            findings[mapped_severity].append(finding)
            self.stats['sast'][mapped_severity] += 1
            self.stats['sast']['total'] += 1
        
        return findings

    def parse_zap_data(self) -> Dict[str, List[Dict]]:
        """Parse and categorize ZAP findings"""
        findings = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        
        if not self.dast_data:
            return findings
        
        # ZAP report structure: site -> alerts
        sites = self.dast_data.get('site', [])
        if not isinstance(sites, list):
            sites = [sites] if sites else []
        
        for site in sites:
            alerts = site.get('alerts', [])
            for alert in alerts:
                # ZAP uses numeric risk codes: 3=High, 2=Medium, 1=Low, 0=Info
                risk_code = str(alert.get('riskcode', '0'))
                
                # Map ZAP risk levels to our severity levels
                severity_map = {
                    '3': 'critical',  # High
                    '2': 'high',      # Medium
                    '1': 'medium',    # Low
                    '0': 'info'       # Informational
                }
                severity = severity_map.get(risk_code, 'info')
                
                instances = alert.get('instances', [])
                
                finding = {
                    'alert': alert.get('alert', 'Unknown'),
                    'description': alert.get('desc', ''),
                    'risk': alert.get('riskdesc', 'Unknown'),
                    'confidence': alert.get('confidence', 'Unknown'),
                    'url_count': len(instances),
                    'urls': [inst.get('uri', '') for inst in instances[:5]],  # First 5 URLs
                    'solution': alert.get('solution', 'No solution provided'),
                    'reference': alert.get('reference', ''),
                    'cwe_id': alert.get('cweid', ''),
                    'wasc_id': alert.get('wascid', ''),
                    'plugin_id': alert.get('pluginid', '')
                }
                
                findings[severity].append(finding)
                self.stats['dast'][severity] += 1
                self.stats['dast']['total'] += 1
        
        return findings

    def generate_html_report(self, sast_findings: Dict, dast_findings: Dict) -> str:
        """Generate comprehensive HTML report"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafetyScan Comprehensive Security Report - {self.project_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .executive-summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.2em;
        }}
        
        .severity-count {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        
        .severity-count:last-child {{
            border-bottom: none;
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .critical {{ background: #ff4757; color: white; }}
        .high {{ background: #ff6348; color: white; }}
        .medium {{ background: #ffa502; color: white; }}
        .low {{ background: #ffd93d; color: #333; }}
        .info {{ background: #6c5ce7; color: white; }}
        
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
        }}
        
        .section-header h2 {{
            font-size: 2em;
            color: #667eea;
            margin-right: 15px;
        }}
        
        .section-badge {{
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
        }}
        
        .finding {{
            background: #f8f9fa;
            border-left: 4px solid #ddd;
            padding: 20px;
            margin: 15px 0;
            border-radius: 5px;
            color: #333;
        }}
        
        .finding.critical {{ border-left-color: #ff4757; }}
        .finding.high {{ border-left-color: #ff6348; }}
        .finding.medium {{ border-left-color: #ffa502; }}
        .finding.low {{ border-left-color: #ffd93d; }}
        .finding.info {{ border-left-color: #6c5ce7; }}
        
        .finding * {{
            color: #333 !important;
        }}
        
        .finding .finding-label {{
            color: #667eea !important;
        }}
        
        .finding .severity-badge {{
            color: white !important;
        }}
        
        .finding .code-block,
        .finding .code-block * {{
            color: #abb2bf !important;
            background: #282c34;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        
        .finding-body {{
            margin: 15px 0;
        }}
        
        .finding-detail {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 4px;
            color: #333;
        }}
        
        .finding-label {{
            font-weight: bold;
            color: #667eea;
            display: inline-block;
            min-width: 100px;
        }}
        
        .finding-detail p, .finding-detail div, .finding-detail span {{
            color: #333;
        }}
        
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .url-list {{
            list-style: none;
            padding: 0;
            color: #333;
        }}
        
        .url-list li {{
            padding: 5px 0;
            border-bottom: 1px solid #eee;
            word-break: break-all;
            color: #333;
        }}
        
        .url-list li:last-child {{
            border-bottom: none;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #27ae60;
            font-size: 1.2em;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 40px;
        }}
        
        .toc {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .toc h3 {{
            color: #667eea;
            margin-bottom: 15px;
        }}
        
        .toc ul {{
            list-style: none;
        }}
        
        .toc li {{
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        
        .toc a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .toc a:hover {{
            text-decoration: underline;
        }}
        
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SafetyScan Security Report</h1>
            <div class="meta">
                <p><strong>Project:</strong> {self.project_name}</p>
                <p><strong>Scan Date:</strong> {self.timestamp}</p>
                <p><strong>Report Type:</strong> Comprehensive Security Analysis (SAST + DAST)</p>
            </div>
        </div>
        
        <div class="toc">
            <h3>📋 Table of Contents</h3>
            <ul>
                <li><a href="#executive-summary">Executive Summary</a></li>
                <li><a href="#sast-findings">SAST Findings (Static Analysis)</a></li>
                <li><a href="#dast-findings">DAST Findings (Dynamic Analysis)</a></li>
                <li><a href="#recommendations">Recommendations</a></li>
            </ul>
        </div>
        
        <div id="executive-summary" class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <p style="margin: 20px 0;">This report provides a comprehensive security analysis of <strong>{self.project_name}</strong>, 
            combining both static (SAST) and dynamic (DAST) application security testing methodologies.</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>🔍 SAST Analysis</h3>
                    <div class="severity-count">
                        <span>Critical:</span>
                        <span class="severity-badge critical">{self.stats['sast']['critical']}</span>
                    </div>
                    <div class="severity-count">
                        <span>High:</span>
                        <span class="severity-badge high">{self.stats['sast']['high']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Medium:</span>
                        <span class="severity-badge medium">{self.stats['sast']['medium']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Low:</span>
                        <span class="severity-badge low">{self.stats['sast']['low']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Info:</span>
                        <span class="severity-badge info">{self.stats['sast']['info']}</span>
                    </div>
                    <div class="severity-count" style="margin-top: 10px; padding-top: 10px; border-top: 2px solid #667eea;">
                        <span><strong>Total Issues:</strong></span>
                        <span><strong>{self.stats['sast']['total']}</strong></span>
                    </div>
                </div>
                
                <div class="stat-card">
                    <h3>🚀 DAST Analysis</h3>
                    <div class="severity-count">
                        <span>Critical:</span>
                        <span class="severity-badge critical">{self.stats['dast']['critical']}</span>
                    </div>
                    <div class="severity-count">
                        <span>High:</span>
                        <span class="severity-badge high">{self.stats['dast']['high']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Medium:</span>
                        <span class="severity-badge medium">{self.stats['dast']['medium']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Low:</span>
                        <span class="severity-badge low">{self.stats['dast']['low']}</span>
                    </div>
                    <div class="severity-count">
                        <span>Info:</span>
                        <span class="severity-badge info">{self.stats['dast']['info']}</span>
                    </div>
                    <div class="severity-count" style="margin-top: 10px; padding-top: 10px; border-top: 2px solid #667eea;">
                        <span><strong>Total Issues:</strong></span>
                        <span><strong>{self.stats['dast']['total']}</strong></span>
                    </div>
                </div>
            </div>
        </div>
"""
        
        # SAST Findings Section
        html += self._generate_sast_section(sast_findings)
        
        # DAST Findings Section
        html += self._generate_dast_section(dast_findings)
        
        # Recommendations Section
        html += self._generate_recommendations()
        
        html += """
        <div class="footer">
            <p>Generated by <strong>SafetyScan</strong> - Automated Security Scanning Tool</p>
            <p>Powered by Semgrep (SAST) and OWASP ZAP (DAST)</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_sast_section(self, findings: Dict) -> str:
        """Generate SAST findings section"""
        html = f"""
        <div id="sast-findings" class="section">
            <div class="section-header">
                <h2>🔍 SAST Findings</h2>
                <span class="section-badge">{self.stats['sast']['total']} Issues</span>
            </div>
            <p style="margin-bottom: 20px; color: #333;">Static Application Security Testing (SAST) analyzes source code to identify security vulnerabilities, 
            coding errors, and potential weaknesses before the application runs.</p>
"""
        
        if self.stats['sast']['total'] == 0:
            html += '<div class="no-findings">✅ No SAST vulnerabilities found! Great job!</div>'
        else:
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if findings.get(severity):
                    html += f'<h3 style="margin: 30px 0 15px 0; color: #2c3e50;">🔴 {severity.upper()} Severity Issues ({len(findings[severity])})</h3>'
                    
                    for finding in findings[severity]:
                        # Clean and escape HTML
                        rule_id = self._clean_and_escape(str(finding.get('rule_id', 'Unknown Rule')))
                        message = self._clean_and_escape(str(finding.get('message', 'No message')))
                        file_path = self._clean_and_escape(str(finding.get('file', 'Unknown')))
                        line = finding.get('line', 0)
                        category = self._clean_and_escape(str(finding.get('category', 'general')))
                        code = self._escape_html(str(finding.get('code', '')))  # Code should be escaped, not stripped
                        
                        html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{rule_id}</div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-detail">
                        <span class="finding-label">Message:</span><br>
                        <div style="color: #333; margin-top: 5px; white-space: pre-wrap;">{message}</div>
                    </div>
                    <div class="finding-detail">
                        <span class="finding-label">File:</span><br>
                        <div style="color: #333; margin-top: 5px;">{file_path} (Line {line})</div>
                    </div>
                    <div class="finding-detail">
                        <span class="finding-label">Category:</span><br>
                        <div style="color: #333; margin-top: 5px;">{category}</div>
                    </div>
"""
                        if finding.get('cwe'):
                            cwe_list = finding['cwe'] if isinstance(finding['cwe'], list) else [finding['cwe']]
                            cwe_escaped = self._escape_html(', '.join(str(c) for c in cwe_list))
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">CWE:</span><br>
                        <div style="color: #333; margin-top: 5px;">{cwe_escaped}</div>
                    </div>
"""
                        if finding.get('owasp'):
                            owasp_list = finding['owasp'] if isinstance(finding['owasp'], list) else [finding['owasp']]
                            owasp_escaped = self._escape_html(', '.join(str(o) for o in owasp_list))
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">OWASP:</span><br>
                        <div style="color: #333; margin-top: 5px;">{owasp_escaped}</div>
                    </div>
"""
                        if code and code.strip():
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">Code Snippet:</span>
                        <pre class="code-block">{code}</pre>
                    </div>
"""
                        html += """
                </div>
            </div>
"""
        
        html += "</div>"
        return html

    def _generate_dast_section(self, findings: Dict) -> str:
        """Generate DAST findings section"""
        html = f"""
        <div id="dast-findings" class="section">
            <div class="section-header">
                <h2>🚀 DAST Findings</h2>
                <span class="section-badge">{self.stats['dast']['total']} Issues</span>
            </div>
            <p style="margin-bottom: 20px; color: #333;">Dynamic Application Security Testing (DAST) analyzes running applications to identify 
            runtime vulnerabilities, configuration issues, and security weaknesses that appear during execution.</p>
"""
        
        if self.stats['dast']['total'] == 0:
            html += '<div class="no-findings">✅ No DAST vulnerabilities found! Excellent security posture!</div>'
        else:
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if findings.get(severity):
                    html += f'<h3 style="margin: 30px 0 15px 0; color: #2c3e50;">🔴 {severity.upper()} Risk Issues ({len(findings[severity])})</h3>'
                    
                    for finding in findings[severity]:
                        # Clean HTML tags from ZAP output, then escape for safe display
                        alert = self._clean_and_escape(str(finding.get('alert', 'Unknown Alert')))
                        description = self._clean_and_escape(str(finding.get('description', 'No description available')))
                        solution = self._clean_and_escape(str(finding.get('solution', 'No solution provided')))
                        confidence = self._clean_and_escape(str(finding.get('confidence', 'Unknown')))
                        risk = self._clean_and_escape(str(finding.get('risk', 'Unknown')))
                        reference = self._strip_html_tags(str(finding.get('reference', '')))
                        
                        # Truncate long descriptions
                        if len(description) > 1000:
                            description = description[:1000] + '...'
                        
                        html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{alert}</div>
                    <span class="severity-badge {severity}">{risk}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-detail">
                        <span class="finding-label">Description:</span><br>
                        <div style="color: #333; margin-top: 5px; white-space: pre-wrap;">{description}</div>
                    </div>
                    <div class="finding-detail">
                        <span class="finding-label">Confidence:</span><br>
                        <div style="color: #333; margin-top: 5px;">{confidence}</div>
                    </div>
                    <div class="finding-detail">
                        <span class="finding-label">Affected URLs:</span><br>
                        <div style="color: #333; margin-top: 5px;">{finding['url_count']} location(s)</div>
                        <ul class="url-list" style="margin-top: 10px;">
"""
                        for url in finding['urls'][:5]:
                            escaped_url = self._escape_html(url)
                            html += f"                            <li>{escaped_url}</li>\n"
                        
                        if finding['url_count'] > 5:
                            html += f"                            <li><em>... and {finding['url_count'] - 5} more</em></li>\n"
                        
                        html += """
                        </ul>
                    </div>
"""
                        if solution and solution.strip() and solution != 'No solution provided':
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">Solution:</span><br>
                        <div style="color: #333; margin-top: 5px; white-space: pre-wrap;">{solution}</div>
                    </div>
"""
                        if finding.get('cwe_id') and str(finding['cwe_id']).strip():
                            cwe_id = self._escape_html(str(finding['cwe_id']))
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">CWE ID:</span><br>
                        <div style="color: #333; margin-top: 5px;">{cwe_id}</div>
                    </div>
"""
                        if reference and reference.strip():
                            # Split references by newlines and make them links if they're URLs
                            refs = [r.strip() for r in reference.split('\n') if r.strip()]
                            html += f"""
                    <div class="finding-detail">
                        <span class="finding-label">Reference:</span><br>
                        <div style="color: #333; margin-top: 5px; word-break: break-all;">
"""
                            for ref in refs:
                                if ref.startswith('http://') or ref.startswith('https://'):
                                    # URL - make it a clickable link
                                    html += f'                            <a href="{self._escape_html(ref)}" target="_blank" style="color: #667eea; display: block; margin: 3px 0;">{self._escape_html(ref)}</a>\n'
                                else:
                                    # Not a URL - just display as text
                                    html += f'                            <div style="margin: 3px 0;">{self._escape_html(ref)}</div>\n'
                            html += """
                        </div>
                    </div>
"""
                        html += """
                </div>
            </div>
"""
        
        html += "</div>"
        return html
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
    
    def _strip_html_tags(self, text: str) -> str:
        """Remove HTML tags from text but preserve content"""
        if not text:
            return ""
        
        import re
        
        # Replace </p>, <br>, </div> etc with newlines to preserve formatting
        text = re.sub(r'</p>|<br\s*/?>|</div>', '\n', text, flags=re.IGNORECASE)
        
        # Remove all other HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Decode common HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        text = text.replace('&quot;', '"')
        text = text.replace('&#x27;', "'")
        text = text.replace('&#39;', "'")
        
        # Clean up multiple newlines
        text = re.sub(r'\n\s*\n', '\n\n', text)
        
        return text.strip()
    
    def _clean_and_escape(self, text: str) -> str:
        """Strip HTML tags first, then escape for safe display"""
        if not text:
            return ""
        # First strip existing HTML tags
        cleaned = self._strip_html_tags(text)
        # Then escape special characters for display
        return self._escape_html(cleaned)

    def _generate_recommendations(self) -> str:
        """Generate recommendations section"""
        total_critical = self.stats['sast']['critical'] + self.stats['dast']['critical']
        total_high = self.stats['sast']['high'] + self.stats['dast']['high']
        
        html = """
        <div id="recommendations" class="section">
            <div class="section-header">
                <h2>💡 Recommendations</h2>
            </div>
"""
        
        if total_critical > 0 or total_high > 0:
            html += """
            <h3 style="color: #ff4757; margin: 20px 0 15px 0;">⚠️ Immediate Action Required</h3>
            <ul style="margin-left: 20px; line-height: 2;">
"""
            if total_critical > 0:
                html += f"<li><strong>Address {total_critical} critical severity issue(s) immediately</strong> - These pose significant security risks</li>"
            if total_high > 0:
                html += f"<li><strong>Prioritize {total_high} high severity issue(s)</strong> - Schedule fixes within the next sprint</li>"
            
            html += """
            </ul>
"""
        
        html += """
            <h3 style="color: #667eea; margin: 30px 0 15px 0;">🎯 Best Practices</h3>
            <ul style="margin-left: 20px; line-height: 2;">
                <li><strong>Regular Scanning:</strong> Integrate SafetyScan into your CI/CD pipeline for continuous security testing</li>
                <li><strong>Code Review:</strong> Review all SAST findings during code reviews before merging</li>
                <li><strong>Security Training:</strong> Educate developers on secure coding practices and common vulnerabilities</li>
                <li><strong>Dependency Updates:</strong> Keep all dependencies up-to-date and scan for known vulnerabilities</li>
                <li><strong>Defense in Depth:</strong> Implement multiple layers of security controls</li>
                <li><strong>Remediation Tracking:</strong> Use issue tracking systems to monitor vulnerability fixes</li>
            </ul>
            
            <h3 style="color: #667eea; margin: 30px 0 15px 0;">📚 Resources</h3>
            <ul style="margin-left: 20px; line-height: 2;">
                <li><a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a> - Most critical web application security risks</li>
                <li><a href="https://cwe.mitre.org/" target="_blank">CWE</a> - Common Weakness Enumeration</li>
                <li><a href="https://semgrep.dev/docs/" target="_blank">Semgrep Documentation</a> - SAST rule writing and customization</li>
                <li><a href="https://www.zaproxy.org/docs/" target="_blank">OWASP ZAP Documentation</a> - DAST configuration and usage</li>
            </ul>
        </div>
"""
        return html

    def generate_markdown_report(self, sast_findings: Dict, dast_findings: Dict) -> str:
        """Generate comprehensive Markdown report"""
        md = f"""# 🛡️ SafetyScan Security Report

**Project:** {self.project_name}  
**Scan Date:** {self.timestamp}  
**Report Type:** Comprehensive Security Analysis (SAST + DAST)

---

## 📊 Executive Summary

This report provides a comprehensive security analysis of **{self.project_name}**, combining both static (SAST) and dynamic (DAST) application security testing methodologies.

### SAST Analysis Statistics

| Severity | Count |
|----------|-------|
| Critical | {self.stats['sast']['critical']} |
| High | {self.stats['sast']['high']} |
| Medium | {self.stats['sast']['medium']} |
| Low | {self.stats['sast']['low']} |
| Info | {self.stats['sast']['info']} |
| **Total** | **{self.stats['sast']['total']}** |

### DAST Analysis Statistics

| Severity | Count |
|----------|-------|
| Critical | {self.stats['dast']['critical']} |
| High | {self.stats['dast']['high']} |
| Medium | {self.stats['dast']['medium']} |
| Low | {self.stats['dast']['low']} |
| Info | {self.stats['dast']['info']} |
| **Total** | **{self.stats['dast']['total']}** |

---

## 🔍 SAST Findings

Static Application Security Testing (SAST) analyzes source code to identify security vulnerabilities.

"""
        
        if self.stats['sast']['total'] == 0:
            md += "✅ **No SAST vulnerabilities found! Great job!**\n\n"
        else:
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if findings := sast_findings.get(severity):
                    md += f"### {severity.upper()} Severity Issues ({len(findings)})\n\n"
                    
                    for i, finding in enumerate(findings, 1):
                        md += f"#### {i}. {finding['rule_id']}\n\n"
                        md += f"**Severity:** {severity.upper()}  \n"
                        md += f"**Message:** {finding['message']}  \n"
                        md += f"**File:** {finding['file']} (Line {finding['line']})  \n"
                        md += f"**Category:** {finding['category']}  \n"
                        
                        if finding.get('cwe'):
                            cwe_list = finding['cwe'] if isinstance(finding['cwe'], list) else [finding['cwe']]
                            md += f"**CWE:** {', '.join(str(c) for c in cwe_list)}  \n"
                        if finding.get('owasp'):
                            owasp_list = finding['owasp'] if isinstance(finding['owasp'], list) else [finding['owasp']]
                            md += f"**OWASP:** {', '.join(str(o) for o in owasp_list)}  \n"
                        if finding.get('code') and str(finding['code']).strip():
                            md += f"\n**Code Snippet:**\n```\n{finding['code']}\n```\n"
                        md += "\n---\n\n"
        
        md += "---\n\n## 🚀 DAST Findings\n\n"
        md += "Dynamic Application Security Testing (DAST) analyzes running applications.\n\n"
        
        if self.stats['dast']['total'] == 0:
            md += "✅ **No DAST vulnerabilities found! Excellent security posture!**\n\n"
        else:
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if findings := dast_findings.get(severity):
                    md += f"### {severity.upper()} Risk Issues ({len(findings)})\n\n"
                    
                    for i, finding in enumerate(findings, 1):
                        md += f"#### {i}. {finding['alert']}\n\n"
                        md += f"**Risk Level:** {finding['risk']}  \n"
                        md += f"**Confidence:** {finding['confidence']}  \n"
                        desc = str(finding.get('description', ''))
                        md += f"**Description:** {desc[:300]}{'...' if len(desc) > 300 else ''}  \n"
                        md += f"**Affected URLs:** {finding['url_count']} location(s)  \n\n"
                        
                        if finding.get('urls'):
                            md += "**Sample URLs:**\n"
                            for url in finding['urls'][:3]:
                                md += f"- {url}\n"
                            if finding['url_count'] > 3:
                                md += f"- *... and {finding['url_count'] - 3} more*\n"
                        
                        if finding.get('solution') and str(finding['solution']).strip():
                            md += f"\n**Solution:** {finding['solution']}  \n"
                        
                        if finding.get('cwe_id'):
                            md += f"**CWE ID:** {finding['cwe_id']}  \n"
                        if finding.get('reference') and str(finding['reference']).strip():
                            md += f"**Reference:** {finding['reference']}  \n"
                        
                        md += "\n---\n\n"
        
        md += self._generate_markdown_recommendations()
        
        return md

    def _generate_markdown_recommendations(self) -> str:
        """Generate recommendations in Markdown format"""
        total_critical = self.stats['sast']['critical'] + self.stats['dast']['critical']
        total_high = self.stats['sast']['high'] + self.stats['dast']['high']
        
        md = "---\n\n## 💡 Recommendations\n\n"
        
        if total_critical > 0 or total_high > 0:
            md += "### ⚠️ Immediate Action Required\n\n"
            if total_critical > 0:
                md += f"- **Address {total_critical} critical severity issue(s) immediately** - These pose significant security risks\n"
            if total_high > 0:
                md += f"- **Prioritize {total_high} high severity issue(s)** - Schedule fixes within the next sprint\n"
            md += "\n"
        
        md += """### 🎯 Best Practices

- **Regular Scanning:** Integrate SafetyScan into your CI/CD pipeline
- **Code Review:** Review all SAST findings during code reviews
- **Security Training:** Educate developers on secure coding practices
- **Dependency Updates:** Keep all dependencies up-to-date
- **Defense in Depth:** Implement multiple layers of security controls

### 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE](https://cwe.mitre.org/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)

---

*Generated by **SafetyScan** - Automated Security Scanning Tool*
"""
        return md

    def generate(self) -> bool:
        """Main method to generate comprehensive reports"""
        print("\n" + "="*60)
        print("  SafetyScan Comprehensive Report Generator")
        print("="*60 + "\n")
        
        # Load data
        if not self.load_data():
            print("✗ Error: No scan data available. Cannot generate report.")
            return False
        
        # Parse findings
        print("\n📊 Parsing scan results...")
        sast_findings = self.parse_semgrep_data() if self.sast_data else {}
        dast_findings = self.parse_zap_data() if self.dast_data else {}
        
        # Generate reports
        print("\n📝 Generating comprehensive reports...")
        
        try:
            # Generate HTML report
            print(f"  → Creating HTML report: {self.output_html}")
            html_content = self.generate_html_report(sast_findings, dast_findings)
            with open(self.output_html, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"  ✓ HTML report saved successfully")
            
            # Generate Markdown report
            print(f"  → Creating Markdown report: {self.output_md}")
            md_content = self.generate_markdown_report(sast_findings, dast_findings)
            with open(self.output_md, 'w', encoding='utf-8') as f:
                f.write(md_content)
            print(f"  ✓ Markdown report saved successfully")
            
        except Exception as e:
            print(f"✗ Error generating reports: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Print summary
        self._print_summary()
        
        return True

    def _print_summary(self):
        """Print report generation summary"""
        print("\n" + "="*60)
        print("  📊 Report Generation Summary")
        print("="*60)
        print(f"\n  Project: {self.project_name}")
        print(f"  Report Directory: {self.report_dir}")
        print(f"\n  SAST Issues Found:")
        print(f"    • Critical: {self.stats['sast']['critical']}")
        print(f"    • High:     {self.stats['sast']['high']}")
        print(f"    • Medium:   {self.stats['sast']['medium']}")
        print(f"    • Low:      {self.stats['sast']['low']}")
        print(f"    • Info:     {self.stats['sast']['info']}")
        print(f"    • Total:    {self.stats['sast']['total']}")
        
        print(f"\n  DAST Issues Found:")
        print(f"    • Critical: {self.stats['dast']['critical']}")
        print(f"    • High:     {self.stats['dast']['high']}")
        print(f"    • Medium:   {self.stats['dast']['medium']}")
        print(f"    • Low:      {self.stats['dast']['low']}")
        print(f"    • Info:     {self.stats['dast']['info']}")
        print(f"    • Total:    {self.stats['dast']['total']}")
        
        total_issues = self.stats['sast']['total'] + self.stats['dast']['total']
        print(f"\n  🔍 Total Issues Detected: {total_issues}")
        
        print(f"\n  📄 Generated Reports:")
        print(f"    • {self.output_html}")
        print(f"    • {self.output_md}")
        print("\n" + "="*60 + "\n")
        
        if self.stats['sast']['critical'] + self.stats['dast']['critical'] > 0:
            print("  ⚠️  CRITICAL ISSUES FOUND - Immediate action required!\n")
        elif self.stats['sast']['high'] + self.stats['dast']['high'] > 0:
            print("  ⚠️  HIGH severity issues found - Please review and address\n")
        elif total_issues == 0:
            print("  ✅ No security issues found - Great job!\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SafetyScan Comprehensive Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'report_dir',
        help='Path to the report directory containing scan results'
    )
    
    parser.add_argument(
        'project_name',
        help='Name of the project being scanned'
    )
    
    args = parser.parse_args()
    
    # Validate report directory
    if not os.path.isdir(args.report_dir):
        print(f"✗ Error: Report directory '{args.report_dir}' does not exist")
        sys.exit(1)
    
    # Generate reports
    generator = ReportGenerator(args.report_dir, args.project_name)
    success = generator.generate()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()