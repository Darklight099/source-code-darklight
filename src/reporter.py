import json
from datetime import datetime
from typing import List, Dict
import os
import html

class ReportGenerator:
    """Generates comprehensive reports in various formats"""
    
    def __init__(self):
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def generate_html_report(self, vulnerabilities: List[Dict], url: str, summary: str) -> str:
        """Generate an HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Group vulnerabilities by severity
        critical = [v for v in vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in vulnerabilities if v['severity'] == 'High']
        medium = [v for v in vulnerabilities if v['severity'] == 'Medium']
        low = [v for v in vulnerabilities if v['severity'] == 'Low']
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .summary {{
            padding: 40px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .summary-content {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            line-height: 1.6;
        }}
        .vulnerabilities {{ padding: 40px; }}
        .vulnerability {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .vuln-header {{
            padding: 20px;
            cursor: pointer;
            background: #fafafa;
            border-left: 5px solid;
        }}
        .vuln-header.critical {{ border-left-color: #dc3545; }}
        .vuln-header.high {{ border-left-color: #fd7e14; }}
        .vuln-header.medium {{ border-left-color: #ffc107; }}
        .vuln-header.low {{ border-left-color: #28a745; }}
        .vuln-title {{ font-size: 1.2em; font-weight: bold; margin-bottom: 5px; }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            margin-left: 10px;
        }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .vuln-location {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        .vuln-content {{ padding: 20px; display: none; }}
        .vuln-content.active {{ display: block; }}
        .code-snippet {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 15px 0;
            font-family: monospace;
        }}
        .ai-analysis {{
            background: #f0f8ff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}
        .ai-section {{
            margin-top: 15px;
            padding: 10px;
            background: white;
            border-left: 3px solid #667eea;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
        }}
        @media (max-width: 768px) {{
            .stats {{ grid-template-columns: repeat(2, 1fr); }}
            .header h1 {{ font-size: 1.5em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Web Vulnerability Analysis Report</h1>
            <p>Target: {url}</p>
            <p>Generated: {timestamp}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-number">{len(vulnerabilities)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-number critical">{len(critical)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-number high">{len(high)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-number medium">{len(medium)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low</div>
                <div class="stat-number low">{len(low)}</div>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-content">
                {summary.replace(chr(10), '<br>')}
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🔍 Detailed Findings</h2>
"""
        
        # Add vulnerabilities
        for vuln in critical + high + medium + low:
            severity_class = vuln['severity'].lower()
            html_content += f"""
            <div class="vulnerability">
                <div class="vuln-header {severity_class}" onclick="toggleVuln(this)">
                    <div class="vuln-title">
                        {vuln['type']}
                        <span class="severity-badge severity-{severity_class}">{vuln['severity']}</span>
                    </div>
                    <div class="vuln-location">📍 {vuln['location']}</div>
                </div>
                <div class="vuln-content">
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    {f'<div class="code-snippet"><pre>{html.escape(vuln["code_snippet"][:500])}</pre></div>' if vuln.get('code_snippet') else ''}
"""
            if vuln.get('ai_analysis'):
                html_content += f"""
                    <div class="ai-analysis">
                        <div class="ai-section">
                            <h4>📖 Explanation</h4>
                            <p>{vuln['ai_analysis'].get('explanation', 'N/A')[:500]}</p>
                        </div>
                        <div class="ai-section">
                            <h4>💥 Impact</h4>
                            <p>{vuln['ai_analysis'].get('impact', 'N/A')[:300]}</p>
                        </div>
                        <div class="ai-section">
                            <h4>🔧 Remediation</h4>
                            <p>{vuln['ai_analysis'].get('remediation', 'N/A')[:300]}</p>
                        </div>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>Generated by Web Vulnerability Analyzer with 🤖 AI assistance</p>
            <p style="font-size: 0.8em; margin-top: 10px;">This report is for educational and security testing purposes only.</p>
        </div>
    </div>
    
    <script>
        function toggleVuln(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('active');
        }
        // Auto-expand critical and high vulnerabilities
        document.querySelectorAll('.vuln-header.critical, .vuln-header.high').forEach(header => {
            header.click();
        });
    </script>
</body>
</html>
"""
        
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def generate_json_report(self, vulnerabilities: List[Dict], url: str, summary: str) -> str:
        """Generate JSON report"""
        report = {
            'target_url': url,
            'scan_timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'ai_summary': summary
        }
        
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename
    
    def generate_markdown_report(self, vulnerabilities: List[Dict], url: str, summary: str) -> str:
        """Generate Markdown report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        md_content = f"""# Web Vulnerability Analysis Report

**Target URL:** {url}
**Scan Date:** {timestamp}
**Total Vulnerabilities:** {len(vulnerabilities)}

## Executive Summary

{summary}

## Vulnerability Statistics

| Severity | Count |
|----------|-------|
"""
        
        severity_counts = {
            'Critical': len([v for v in vulnerabilities if v['severity'] == 'Critical']),
            'High': len([v for v in vulnerabilities if v['severity'] == 'High']),
            'Medium': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
            'Low': len([v for v in vulnerabilities if v['severity'] == 'Low'])
        }
        
        for severity, count in severity_counts.items():
            md_content += f"| {severity} | {count} |\n"
        
        md_content += "\n## Detailed Findings\n\n"
        
        for vuln in vulnerabilities:
            md_content += f"""
### {vuln['type']} - {vuln['severity']}

- **Location:** {vuln['location']}
- **Description:** {vuln['description']}

"""
            if vuln.get('code_snippet'):
                md_content += f"**Code Snippet:**\n```html\n{vuln['code_snippet'][:300]}\n```\n\n"
            
            if vuln.get('ai_analysis'):
                md_content += f"""
**AI Analysis:**

- **Explanation:** {vuln['ai_analysis'].get('explanation', 'N/A')[:300]}
- **Impact:** {vuln['ai_analysis'].get('impact', 'N/A')[:200]}
- **Remediation:** {vuln['ai_analysis'].get('remediation', 'N/A')[:200]}

"""
            
            md_content += "---\n\n"
        
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return filename
