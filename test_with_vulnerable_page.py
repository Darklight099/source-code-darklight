import asyncio
import sys
sys.path.insert(0, '.')

from src.scraper import WebScraper
from src.analyzer import VulnerabilityAnalyzer

async def test():
    config = {
        'scan': {'timeout': 10, 'user_agent': 'Test/1.0'},
        'vulnerability_patterns': {
            'xss': [r'document\.write', r'innerHTML', r'eval\(', r'location\.hash'],
            'sql_injection': [r'SELECT.*FROM', r'INSERT INTO'],
            'command_injection': [r'system\(', r'exec\(', r'shell_exec\('],
            'sensitive_data': [r'password', r'secret', r'api_key', r'token']
        }
    }
    
    scraper = WebScraper(config)
    analyzer = VulnerabilityAnalyzer(config)
    
    # First, test with our local vulnerable file
    print("[*] Testing with local vulnerable HTML file...")
    print("=" * 50)
    
    # Since we're using a local file, we need to serve it or read directly
    # For now, let's test by reading the file directly
    with open('examples/sample_vulnerable_site.html', 'r') as f:
        html_content = f.read()
    
    # Create a mock page data structure
    mock_page = {
        'url': 'file:///test_vulnerable_site.html',
        'html': html_content,
        'scripts': [],
        'styles': [],
        'inline_handlers': [],
        'forms': [],
        'links': []
    }
    
    # Parse the HTML to extract components
    from bs4 import BeautifulSoup
    import jsbeautifier
    from urllib.parse import urljoin
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract JavaScript
    for script in soup.find_all('script'):
        if script.string:
            try:
                mock_page['scripts'].append(jsbeautifier.beautify(script.string))
            except:
                mock_page['scripts'].append(script.string)
    
    # Extract inline handlers
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.startswith('on'):
                mock_page['inline_handlers'].append({
                    'tag': tag.name,
                    'event': attr,
                    'value': tag[attr]
                })
    
    # Extract forms
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get'),
            'inputs': []
        }
        for input_tag in form.find_all('input'):
            form_data['inputs'].append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            })
        mock_page['forms'].append(form_data)
    
    print(f"[*] Parsed page with:")
    print(f"    - {len(mock_page['scripts'])} script blocks")
    print(f"    - {len(mock_page['inline_handlers'])} inline handlers")
    print(f"    - {len(mock_page['forms'])} forms")
    print()
    
    # Analyze for vulnerabilities
    print("[*] Analyzing for vulnerabilities...")
    vulns = analyzer.analyze_all(mock_page)
    
    print(f"\n[*] Found {len(vulns)} potential vulnerabilities:\n")
    
    # Display vulnerabilities by severity
    critical = [v for v in vulns if v['severity'] == 'Critical']
    high = [v for v in vulns if v['severity'] == 'High']
    medium = [v for v in vulns if v['severity'] == 'Medium']
    low = [v for v in vulns if v['severity'] == 'Low']
    
    if critical:
        print("🔴 CRITICAL VULNERABILITIES:")
        for vuln in critical:
            print(f"  - {vuln['type']}")
            print(f"    Description: {vuln['description']}")
            print()
    
    if high:
        print("🟠 HIGH VULNERABILITIES:")
        for vuln in high:
            print(f"  - {vuln['type']}")
            print(f"    Description: {vuln['description']}")
            print()
    
    if medium:
        print("🟡 MEDIUM VULNERABILITIES:")
        for vuln in medium:
            print(f"  - {vuln['type']}")
            print(f"    Description: {vuln['description']}")
            print()
    
    if low:
        print("🟢 LOW VULNERABILITIES:")
        for vuln in low:
            print(f"  - {vuln['type']}")
            print(f"    Description: {vuln['description']}")
            print()
    
    print("=" * 50)
    print(f"Total: {len(vulns)} vulnerabilities found")

if __name__ == "__main__":
    asyncio.run(test())
