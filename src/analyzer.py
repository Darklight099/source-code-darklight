import re
from typing import Dict, List, Any, Set
import logging
from colorama import Fore, Style
from bs4 import BeautifulSoup

class VulnerabilityAnalyzer:
    """Analyzes source code for potential vulnerabilities"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.patterns = config['vulnerability_patterns']
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities = []
        
    def analyze_all(self, page_data: Dict) -> List[Dict]:
        """Run all analysis on page data"""
        vulnerabilities = []
        
        # Analyze HTML
        vulnerabilities.extend(self.analyze_html(page_data['html'], page_data['url']))
        
        # Analyze JavaScript
        for script in page_data['scripts']:
            vulnerabilities.extend(self.analyze_javascript(script, page_data['url']))
        
        # Analyze inline handlers
        for handler in page_data['inline_handlers']:
            vulnerabilities.extend(self.analyze_inline_handler(handler, page_data['url']))
        
        # Analyze forms
        for form in page_data['forms']:
            vulnerabilities.extend(self.analyze_form(form, page_data['url']))
        
        return vulnerabilities
    
    def analyze_html(self, html: str, url: str) -> List[Dict]:
        """Analyze HTML for vulnerabilities"""
        vulns = []
        
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check for coupon/code forms (SQL injection targets)
        for form in soup.find_all('form'):
            for input_field in form.find_all('input'):
                input_name = input_field.get('name', '').lower()
                input_id = input_field.get('id', '').lower()
                input_placeholder = input_field.get('placeholder', '').lower()
                
                # Check for coupon/code related inputs
                if any(keyword in input_name or keyword in input_id or keyword in input_placeholder 
                       for keyword in ['coupon', 'code', 'voucher', 'discount', 'promo']):
                    vulns.append({
                        'type': 'sql_injection_coupon_code',
                        'severity': 'Critical',
                        'location': url,
                        'description': f'Coupon/code input field "{input_field.get("name", "")}" found. This is a common SQL injection target.',
                        'code_snippet': f'<input type="{input_field.get("type", "text")}" name="{input_field.get("name", "")}">'
                    })
        
        # Check for missing CSRF tokens
        if '<form' in html and 'csrf' not in html.lower() and 'token' not in html.lower():
            vulns.append({
                'type': 'missing_csrf',
                'severity': 'Medium',
                'location': url,
                'description': 'Forms found without CSRF protection',
                'code_snippet': self.extract_code_snippet(html, '<form', 100)
            })
        
        # Check for insecure forms
        if 'method="get"' in html.lower() and '<form' in html:
            vulns.append({
                'type': 'insecure_form_method',
                'severity': 'Low',
                'location': url,
                'description': 'Form using GET method for data submission',
                'code_snippet': self.extract_code_snippet(html, '<form', 100)
            })
        
        # Check for comments containing sensitive info
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comments:
            sensitive_keywords = ['password', 'api', 'key', 'secret', 'token', 'todo', 'sql', 'query']
            for keyword in sensitive_keywords:
                if keyword in comment.lower():
                    vulns.append({
                        'type': 'sensitive_info_comment',
                        'severity': 'Medium',
                        'location': url,
                        'description': f'Comment contains sensitive keyword: {keyword}',
                        'code_snippet': comment[:200]
                    })
                    break
        
        return vulns
    
    def analyze_javascript(self, js: str, url: str) -> List[Dict]:
        """Analyze JavaScript for vulnerabilities"""
        vulns = []
        
        # Check for SQL injection patterns in JavaScript
        sql_patterns = [
            r'(SELECT|INSERT|UPDATE|DELETE|DROP).*?\+',
            r'\$\{.*?\}.*?(SELECT|INSERT|UPDATE)',
            r'\.query\(.*?\$',
            r'\.exec\(.*?\$',
            r'mysql_query\(.*?\$',
            r'mysqli_query\(.*?\$'
        ]
        
        for pattern in sql_patterns:
            matches = re.finditer(pattern, js, re.IGNORECASE)
            for match in matches:
                vulns.append({
                    'type': 'sql_injection_javascript',
                    'severity': 'Critical',
                    'location': url,
                    'description': f'Potential SQL injection in JavaScript: {match.group()[:100]}',
                    'code_snippet': self.extract_code_snippet(js, match.group(), 150)
                })
        
        # Check for XSS vectors
        xss_patterns = self.patterns.get('xss', [])
        for pattern in xss_patterns:
            matches = re.finditer(pattern, js, re.IGNORECASE)
            for match in matches:
                vulns.append({
                    'type': 'xss_vulnerability',
                    'severity': 'High',
                    'location': url,
                    'description': f'Potential XSS vector detected: {match.group()}',
                    'code_snippet': self.extract_code_snippet(js, match.group(), 150)
                })
        
        # Check for eval usage
        if 'eval(' in js:
            vulns.append({
                'type': 'dangerous_function',
                'severity': 'High',
                'location': url,
                'description': 'Usage of eval() function - potential code injection risk',
                'code_snippet': self.extract_code_snippet(js, 'eval(', 150)
            })
        
        # Check for document.write usage
        if 'document.write' in js:
            vulns.append({
                'type': 'dangerous_function',
                'severity': 'Medium',
                'location': url,
                'description': 'Usage of document.write() - can lead to XSS if used with user input',
                'code_snippet': self.extract_code_snippet(js, 'document.write', 150)
            })
        
        # Check for hardcoded secrets
        secrets_pattern = r'(api[_-]?key|secret|token|password)\s*=\s*["\']([^"\']+)["\']'
        matches = re.finditer(secrets_pattern, js, re.IGNORECASE)
        for match in matches:
            vulns.append({
                'type': 'hardcoded_secret',
                'severity': 'Critical',
                'location': url,
                'description': f'Hardcoded {match.group(1)} detected',
                'code_snippet': match.group(0)
            })
        
        return vulns
    
    def analyze_inline_handler(self, handler: Dict, url: str) -> List[Dict]:
        """Analyze inline event handlers for vulnerabilities"""
        vulns = []
        
        # Check for potentially dangerous inline handlers
        dangerous_handlers = ['onclick', 'onload', 'onerror', 'onmouseover', 'onsubmit']
        if handler['event'] in dangerous_handlers:
            if any(char in handler['value'] for char in ['<', '>', '"', "'", ';', '(', ')']):
                vulns.append({
                    'type': 'inline_xss',
                    'severity': 'High',
                    'location': url,
                    'description': f'Potential XSS in inline {handler["event"]} handler',
                    'code_snippet': f'{handler["tag"]} {handler["event"]}="{handler["value"]}"'
                })
        
        return vulns
    
    def analyze_form(self, form: Dict, url: str) -> List[Dict]:
        """Analyze forms for security issues including potential SQL injection points"""
        vulns = []
        
        # Check if form action is empty (submits to same page)
        if not form['action']:
            vulns.append({
                'type': 'self_submitting_form',
                'severity': 'Low',
                'location': url,
                'description': 'Form submits to the same page - potential CSRF risk',
                'code_snippet': f'Form with action="{form["action"]}"'
            })
        
        # Check for password fields without HTTPS
        for input_field in form['inputs']:
            if input_field['type'] == 'password':
                vulns.append({
                    'type': 'insecure_password_transmission',
                    'severity': 'High',
                    'location': url,
                    'description': 'Password field found - ensure HTTPS is used',
                    'code_snippet': f'Password input in form: {input_field}'
                })
            
            # Detect potential SQL injection points in form inputs
            if input_field['type'] in ['text', 'search', 'number', 'email', 'hidden']:
                # Check for common SQL injection indicators in input names
                sqli_indicators = ['user', 'username', 'email', 'id', 'code', 'coupon', 'search', 'query', 'name', 'product', 'category']
                input_name = input_field.get('name', '').lower()
                
                if any(indicator in input_name for indicator in sqli_indicators):
                    vulns.append({
                        'type': 'potential_sql_injection',
                        'severity': 'Critical',
                        'location': url,
                        'description': f"Input field '{input_field['name']}' may be vulnerable to SQL injection. This field name suggests it might be used in database queries.",
                        'code_snippet': f'<input type="{input_field["type"]}" name="{input_field["name"]}">'
                    })
        
        return vulns
    
    def extract_code_snippet(self, code: str, pattern: str, context_chars: int = 100) -> str:
        """Extract a code snippet around the pattern"""
        try:
            index = code.find(pattern)
            if index == -1:
                return pattern
            
            start = max(0, index - context_chars)
            end = min(len(code), index + len(pattern) + context_chars)
            snippet = code[start:end]
            
            # Add ellipsis if needed
            if start > 0:
                snippet = '...' + snippet
            if end < len(code):
                snippet = snippet + '...'
            
            return snippet.strip()
        except:
            return pattern
