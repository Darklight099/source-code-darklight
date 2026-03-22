#!/usr/bin/env python3
"""
Web Vulnerability Analyzer with AI Integration
A tool that analyzes websites for security vulnerabilities using Ollama AI
"""

import asyncio
import argparse
import sys
import yaml
import logging
from colorama import init, Fore, Style
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
import os

from src.scraper import WebScraper
from src.analyzer import VulnerabilityAnalyzer
from src.ollama_client import OllamaClient
from src.reporter import ReportGenerator

# Initialize colorama
init(autoreset=True)
console = Console()

class WebVulnerabilityAnalyzer:
    """Main application class"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the analyzer with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.scraper = WebScraper(self.config)
        self.analyzer = VulnerabilityAnalyzer(self.config)
        self.ollama_client = OllamaClient(self.config)
        self.reporter = ReportGenerator()
    
    async def analyze_url(self, url: str, crawl: bool = False, max_pages: int = 50, use_ai: bool = True, ai_limit: int = 5, delay: float = 0.5) -> None:
        """Main analysis workflow with CPU optimization"""
        console.print(Panel.fit(
            f"[bold cyan]Web Vulnerability Analyzer[/bold cyan]\nTarget: {url}",
            border_style="cyan"
        ))
        
        # Step 1: Scrape the website
        console.print(f"\n[bold yellow]Step 1: Scraping website...[/bold yellow]")
        if crawl:
            console.print(f"[yellow]Crawling mode enabled (max {max_pages} pages)[/yellow]")
            pages_data = await self.scraper.crawl_site(url, max_pages)
        else:
            console.print("[yellow]Single page mode[/yellow]")
            page_data = await self.scraper.fetch_page(url)
            pages_data = [page_data] if page_data else []
        
        if not pages_data:
            console.print(f"[bold red]Failed to fetch data from {url}[/bold red]")
            return
        
        console.print(f"[green]✓ Successfully fetched {len(pages_data)} pages[/green]")
        
        # Step 2: Analyze for vulnerabilities
        console.print(f"\n[bold yellow]Step 2: Analyzing code for vulnerabilities...[/bold yellow]")
        all_vulnerabilities = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing pages...", total=len(pages_data))
            
            for page_data in pages_data:
                vulns = self.analyzer.analyze_all(page_data)
                all_vulnerabilities.extend(vulns)
                progress.advance(task)
        
        console.print(f"[green]✓ Found {len(all_vulnerabilities)} potential vulnerabilities[/green]")
        
        # Step 3: Get AI analysis from Ollama (if enabled)
        if use_ai and all_vulnerabilities:
            console.print(f"\n[bold yellow]Step 3: Getting AI analysis from Ollama...[/bold yellow]")
            console.print(f"[yellow]AI limit set to {ai_limit} vulnerabilities (use --ai-limit to change)[/yellow]")
            
            analyzed_vulnerabilities = await self.ollama_client.analyze_multiple_vulnerabilities(
                all_vulnerabilities, 
                max_ai_analyses=ai_limit
            )
            
            # Generate summary
            summary = await self.ollama_client.generate_summary(analyzed_vulnerabilities)
        else:
            if not use_ai:
                console.print("[yellow]AI analysis disabled[/yellow]")
            analyzed_vulnerabilities = all_vulnerabilities
            summary = f"Found {len(all_vulnerabilities)} vulnerabilities. Run with AI enabled for detailed analysis."
        
        # Step 4: Generate reports
        console.print(f"\n[bold yellow]Step 4: Generating reports...[/bold yellow]")
        
        html_report = self.reporter.generate_html_report(analyzed_vulnerabilities, url, summary)
        json_report = self.reporter.generate_json_report(analyzed_vulnerabilities, url, summary)
        md_report = self.reporter.generate_markdown_report(analyzed_vulnerabilities, url, summary)
        
        console.print(f"[green]✓ HTML Report: {html_report}[/green]")
        console.print(f"[green]✓ JSON Report: {json_report}[/green]")
        console.print(f"[green]✓ Markdown Report: {md_report}[/green]")
        
        # Display summary
        self.display_summary(analyzed_vulnerabilities, summary)
    
    def display_summary(self, vulnerabilities: list, summary: str) -> None:
        """Display a summary of findings"""
        if not vulnerabilities:
            console.print(Panel(
                "[bold green]No vulnerabilities found! The website appears to be secure.[/bold green]",
                title="Summary",
                border_style="green"
            ))
            return
        
        # Create severity table
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        table = Table(title="Vulnerability Summary")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="right")
        
        for severity, count in severity_counts.items():
            if count > 0:
                style = {
                    'Critical': 'red',
                    'High': 'yellow',
                    'Medium': 'blue',
                    'Low': 'green'
                }[severity]
                table.add_row(severity, str(count), style=style)
        
        console.print(table)
        
        # Display AI summary
        console.print(Panel(
            summary[:500] + ("..." if len(summary) > 500 else ""),
            title="AI Summary",
            border_style="cyan"
        ))
        
        # Display top 3 critical/high vulnerabilities
        critical_high = [v for v in vulnerabilities if v['severity'] in ['Critical', 'High']]
        if critical_high:
            console.print("\n[bold red]Top Critical/High Priority Issues:[/bold red]")
            for i, vuln in enumerate(critical_high[:3], 1):
                console.print(f"{i}. [red]{vuln['type']}[/red] - {vuln['description'][:100]}...")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Web Vulnerability Analyzer with AI")
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling mode")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--config", default="config.yaml", help="Configuration file path")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--ai-limit", type=int, default=5, help="Maximum number of vulnerabilities to analyze with AI (default: 5)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    
    args = parser.parse_args()
    
    # Check if config file exists
    if not os.path.exists(args.config):
        console.print(f"[red]Error: Config file {args.config} not found![/red]")
        sys.exit(1)
    
    # Initialize and run analyzer
    analyzer = WebVulnerabilityAnalyzer(args.config)
    
    try:
        await analyzer.analyze_url(
            args.url, 
            args.crawl, 
            args.max_pages, 
            use_ai=not args.no_ai,
            ai_limit=args.ai_limit,
            delay=args.delay
        )
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
