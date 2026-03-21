import requests
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Optional
import logging
from colorama import Fore, Style
import jsbeautifier
import cssutils

class WebScraper:
    """Handles website source code extraction and inspection"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.visited_urls: Set[str] = set()
        self.logger = logging.getLogger(__name__)
        
    async def fetch_page(self, url: str) -> Optional[Dict]:
        """Fetch a single page and extract its components"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config['scan']['timeout']),
                    headers={'User-Agent': self.config['scan']['user_agent']}
                ) as response:
                    if response.status == 200:
                        html = await response.text()
                        return await self.parse_page(url, html)
                    else:
                        self.logger.warning(f"Failed to fetch {url}: Status {response.status}")
                        return None
        except Exception as e:
            self.logger.error(f"Error fetching {url}: {str(e)}")
            return None
    
    async def parse_page(self, url: str, html: str) -> Dict:
        """Parse HTML and extract all relevant components"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract JavaScript code
        scripts = []
        for script in soup.find_all('script'):
            if script.string:
                try:
                    scripts.append(jsbeautifier.beautify(script.string))
                except:
                    scripts.append(script.string)
            elif script.get('src'):
                script_url = urljoin(url, script.get('src'))
                scripts.append(await self.fetch_external_script(script_url))
        
        # Extract CSS
        styles = []
        for style in soup.find_all('style'):
            if style.string:
                styles.append(style.string)
        
        # Extract inline event handlers (potential XSS vectors)
        inline_handlers = []
        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.startswith('on'):
                    inline_handlers.append({
                        'tag': tag.name,
                        'event': attr,
                        'value': tag[attr]
                    })
        
        # Extract forms (potential injection points)
        forms = []
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
            forms.append(form_data)
        
        return {
            'url': url,
            'html': html,
            'scripts': scripts,
            'styles': styles,
            'inline_handlers': inline_handlers,
            'forms': forms,
            'links': [urljoin(url, link.get('href')) for link in soup.find_all('a') if link.get('href')]
        }
    
    async def fetch_external_script(self, url: str) -> str:
        """Fetch external JavaScript file"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        try:
                            return jsbeautifier.beautify(text)
                        except:
                            return text
        except:
            pass
        return ""
    
    async def crawl_site(self, start_url: str, max_pages: int = 50) -> List[Dict]:
        """Crawl the website and collect all pages"""
        pages_data = []
        to_visit = [start_url]
        visited_count = 0
        
        while to_visit and visited_count < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in self.visited_urls:
                continue
                
            self.visited_urls.add(current_url)
            
            print(f"{Fore.CYAN}[+] Crawling: {current_url}{Style.RESET_ALL}")
            
            page_data = await self.fetch_page(current_url)
            if page_data:
                pages_data.append(page_data)
                visited_count += 1
                
                # Add new links to visit
                for link in page_data['links']:
                    if self.is_same_domain(start_url, link) and link not in self.visited_urls:
                        to_visit.append(link)
        
        return pages_data
    
    def is_same_domain(self, base_url: str, test_url: str) -> bool:
        """Check if URLs belong to same domain"""
        base_domain = urlparse(base_url).netloc
        test_domain = urlparse(test_url).netloc
        return base_domain == test_domain
