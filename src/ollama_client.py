import aiohttp
import json
import asyncio
from typing import Dict, List, Optional
import logging
from colorama import Fore, Style

class OllamaClient:
    """Client for interacting with Ollama AI for vulnerability analysis and education"""
    
    def __init__(self, config: Dict):
        self.config = config['ollama']
        self.base_url = self.config['base_url']
        self.model = self.config['model']
        self.temperature = self.config['temperature']
        self.max_tokens = self.config['max_tokens']
        self.logger = logging.getLogger(__name__)
        
    async def analyze_vulnerability(self, vulnerability: Dict) -> Dict:
        """Send vulnerability to Ollama for detailed analysis with rate limiting"""
        # Add delay to prevent CPU spikes
        await asyncio.sleep(0.5)
        
        try:
            prompt = self._create_analysis_prompt(vulnerability)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": self.temperature,
                            "num_predict": self.max_tokens
                        }
                    },
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return self._parse_ollama_response(result['response'], vulnerability)
                    else:
                        self.logger.error(f"Ollama API error: {response.status}")
                        return self._create_fallback_analysis(vulnerability)
        except asyncio.TimeoutError:
            self.logger.error(f"Ollama timeout for {vulnerability['type']}")
            return self._create_fallback_analysis(vulnerability)
        except Exception as e:
            self.logger.error(f"Error calling Ollama: {str(e)}")
            return self._create_fallback_analysis(vulnerability)
    
    async def analyze_multiple_vulnerabilities(self, vulnerabilities: List[Dict], max_ai_analyses: int = 5) -> List[Dict]:
        """Analyze multiple vulnerabilities with Ollama with CPU limits"""
        analyzed_vulns = []
        
        if not vulnerabilities:
            return analyzed_vulns
        
        # Limit to max_ai_analyses to prevent CPU overload
        to_analyze = vulnerabilities[:max_ai_analyses]
        remaining = vulnerabilities[max_ai_analyses:]
        
        if remaining:
            print(f"{Fore.YELLOW}[!] Limiting AI analysis to first {max_ai_analyses} vulnerabilities (remaining {len(remaining)} will use fallback){Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] Starting AI analysis for {len(to_analyze)} vulnerabilities...{Style.RESET_ALL}")
        
        # Process with concurrency limit of 2 to prevent CPU spikes
        semaphore = asyncio.Semaphore(2)
        
        async def process_with_limit(vuln, index):
            async with semaphore:
                print(f"{Fore.CYAN}[*] Analyzing {index}/{len(to_analyze)}: {vuln['type']} ({vuln['severity']}){Style.RESET_ALL}")
                analyzed = await self.analyze_vulnerability(vuln)
                return analyzed
        
        # Process AI analyses with concurrency limit
        tasks = [process_with_limit(vuln, i+1) for i, vuln in enumerate(to_analyze)]
        ai_analyzed = await asyncio.gather(*tasks)
        analyzed_vulns.extend(ai_analyzed)
        
        # Add fallback analysis for remaining vulnerabilities
        if remaining:
            print(f"{Fore.YELLOW}[*] Using fallback analysis for remaining {len(remaining)} vulnerabilities{Style.RESET_ALL}")
            for vuln in remaining:
                analyzed_vulns.append(self._create_fallback_analysis(vuln))
        
        return analyzed_vulns
    
    def _create_analysis_prompt(self, vulnerability: Dict) -> str:
        """Create a detailed prompt for Ollama"""
        prompt = 'You are a cybersecurity expert analyzing a web vulnerability. Provide a detailed analysis of the following vulnerability:\n\n'
        prompt += f'Vulnerability Type: {vulnerability["type"]}\n'
        prompt += f'Severity: {vulnerability["severity"]}\n'
        prompt += f'Location: {vulnerability["location"]}\n'
        prompt += f'Description: {vulnerability["description"]}\n'
        prompt += 'Code Snippet:\n```\n'
        prompt += vulnerability.get('code_snippet', 'No code snippet available')
        prompt += '\n```\n\n'
        prompt += 'Please provide:\n'
        prompt += '1. EXPLANATION: What makes this a vulnerability? Explain in simple terms.\n'
        prompt += '2. IMPACT: What could an attacker do if they exploit this?\n'
        prompt += '3. REMEDIATION: How to fix this vulnerability (with code examples if applicable)\n'
        prompt += '4. PREVENTION: Best practices to prevent this type of vulnerability in the future\n\n'
        prompt += 'Format your response with these sections clearly marked. Keep responses concise (max 200 words).'
        return prompt
    
    def _parse_ollama_response(self, response: str, original_vuln: Dict) -> Dict:
        """Parse Ollama's response into structured format"""
        sections = {
            'explanation': '',
            'impact': '',
            'remediation': '',
            'prevention': ''
        }
        
        current_section = None
        for line in response.split('\n'):
            line_lower = line.lower()
            if 'explanation:' in line_lower:
                current_section = 'explanation'
                line = line.replace('Explanation:', '').strip()
            elif 'impact:' in line_lower:
                current_section = 'impact'
                line = line.replace('Impact:', '').strip()
            elif 'remediation:' in line_lower:
                current_section = 'remediation'
                line = line.replace('Remediation:', '').strip()
            elif 'prevention:' in line_lower:
                current_section = 'prevention'
                line = line.replace('Prevention:', '').strip()
            
            if current_section and line:
                sections[current_section] += line + '\n'
        
        for key in sections:
            sections[key] = sections[key].strip()
        
        return {
            **original_vuln,
            'ai_analysis': sections
        }
    
    def _create_fallback_analysis(self, vulnerability: Dict) -> Dict:
        """Create a fallback analysis if Ollama is not available"""
        return {
            **vulnerability,
            'ai_analysis': {
                'explanation': f"This is a {vulnerability['type']} vulnerability. {vulnerability['description']}",
                'impact': "The impact depends on the specific context, but generally this could lead to security breaches, data leaks, or unauthorized access.",
                'remediation': "Review the code and implement proper security measures. Consider using security libraries and following OWASP guidelines.",
                'prevention': "Follow secure coding practices, conduct regular security audits, and stay updated with the latest security best practices."
            }
        }
    
    async def generate_summary(self, vulnerabilities: List[Dict]) -> str:
        """Generate a comprehensive summary of all findings"""
        if not vulnerabilities:
            return "No vulnerabilities found. The website appears to be secure based on the analysis."
        
        prompt = f"Generate a comprehensive security summary based on these {len(vulnerabilities)} vulnerabilities found during the scan:\n\n"
        
        # Limit to first 10 vulnerabilities to keep prompt size manageable
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            prompt += f"{i}. {vuln['type']} (Severity: {vuln['severity']}) - {vuln['description'][:100]}\n"
        
        prompt += "\n\nPlease provide:\n"
        prompt += "1. Executive Summary\n"
        prompt += "2. Critical Issues (highest priority)\n"
        prompt += "3. Recommendations for Fixing\n"
        prompt += "4. Overall Security Score (0-100)\n"
        prompt += "5. Next Steps for Improvement\n\n"
        prompt += "Be professional and concise."
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 1000
                        }
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result['response']
                    else:
                        return "Unable to generate summary from Ollama. Please review the individual vulnerabilities above."
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            return "Error generating AI summary. Please check the vulnerabilities manually."
