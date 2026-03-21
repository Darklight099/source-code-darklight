#!/usr/bin/env python3
"""Test the full tool with AI analysis"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scraper import WebScraper
from src.analyzer import VulnerabilityAnalyzer
from src.ollama_client import OllamaClient
from bs4 import BeautifulSoup
import jsbeautifier

async def test_with_ai():
    config = {
        'scan': {'timeout': 10, 'user_agent': 'Test/1.0'},
        'ollama': {
            'model': 'llama3.2:latest',
            'base_url': 'http://localhost:11434',
            'temperature': 0.3,
            'max_tokens': 500
        },
        'vulnerability_patterns': {
            'xss': [r'document\.write', r'innerHTML', r'eval\(', r'location\.hash'],
            'sql_injection': [r'SELECT.*FROM', r'INSERT INTO'],
            'command_injection': [r'system\(', r'exec\(', r'shell_exec\('],
            'sensitive_data': [r'password', r'secret', r'api_key', r'token']
        }
    }
    
    print("[*] Testing with AI analysis...")
    print("=" * 60)
    
    # Check if Ollama is running
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:11434/api/tags') as response:
                if response.status == 200:
                    print("✓ Ollama is running")
                else:
                    print("⚠️  Ollama not responding, will use fallback mode")
    except:
        print("⚠️  Cannot connect to Ollama, will use fallback mode")
    
    # Read the vulnerable HTML file
    html_path = 'examples/sample_vulnerable_site.html'
    
    if not os.path.exists(html_path):
        print(f"[!] Error: {html_path} not found!")
        return
    
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Parse the HTML
    soup = BeautifulSoup(html_content, 'html.parser')
    
    mock_page = {
        'url': 'file:///test_vulnerable_site.html',
        'html': html_content,
        'scripts': [],
        'styles': [],
        'inline_handlers': [],
        'forms': [],
        'links': []
    }
    
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
    
    # Analyze vulnerabilities
    analyzer = VulnerabilityAnalyzer(config)
    vulnerabilities = analyzer.analyze_all(mock_page)
    
    print(f"\n[*] Found {len(vulnerabilities)} vulnerabilities")
    print("[*] Getting AI analysis for first 3 vulnerabilities (this may take a moment)...\n")
    
    # Get AI analysis for first 3 vulnerabilities (to save time)
    ollama = OllamaClient(config)
    analyzed_vulns = []
    
    for i, vuln in enumerate(vulnerabilities[:3], 1):
        print(f"[*] Analyzing {i}/3: {vuln['type']}...")
        try:
            analyzed = await ollama.analyze_vulnerability(vuln)
            analyzed_vulns.append(analyzed)
            print(f"    ✓ Analysis complete")
            print()
        except Exception as e:
            print(f"    ✗ Error: {e}")
            print()
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 AI ANALYSIS RESULTS")
    print("=" * 60)
    
    for vuln in analyzed_vulns:
        print(f"\n🔍 {vuln['type'].upper()} ({vuln['severity']})")
        print(f"   📍 Location: {vuln['location']}")
        print(f"   📝 Description: {vuln['description']}")
        
        if vuln.get('code_snippet'):
            print(f"\n   💻 Code Snippet:")
            print(f"      {vuln['code_snippet'][:150]}...")
        
        if vuln.get('ai_analysis'):
            ai = vuln['ai_analysis']
            
            if ai.get('explanation'):
                print(f"\n   📖 EXPLANATION:")
                explanation = ai['explanation'][:300]
                for line in explanation.split('\n')[:5]:
                    print(f"      {line}")
            
            if ai.get('impact'):
                print(f"\n   💥 IMPACT:")
                impact = ai['impact'][:200]
                for line in impact.split('\n')[:3]:
                    print(f"      {line}")
            
            if ai.get('remediation'):
                print(f"\n   🔧 REMEDIATION:")
                remediation = ai['remediation'][:200]
                for line in remediation.split('\n')[:3]:
                    print(f"      {line}")
        
        print("\n" + "-" * 40)
    
    # Generate summary
    print("\n[*] Generating executive summary...")
    try:
        summary = await ollama.generate_summary(analyzed_vulns)
        print("\n📝 EXECUTIVE SUMMARY")
        print("=" * 60)
        print(summary)
        print("=" * 60)
    except Exception as e:
        print(f"Error generating summary: {e}")
    
    print("\n✅ Test complete!")

if __name__ == "__main__":
    asyncio.run(test_with_ai())
