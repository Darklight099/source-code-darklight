import asyncio
from src.scraper import WebScraper

async def test():
    config = {'scan': {'timeout': 10, 'user_agent': 'Test/1.0'}}
    scraper = WebScraper(config)
    
    # Test with a simple website
    result = await scraper.fetch_page('https://httpbin.org/html')
    
    if result:
        print(f"✓ Successfully fetched page: {result['url']}")
        print(f"✓ Found {len(result['scripts'])} scripts")
        print(f"✓ Found {len(result['forms'])} forms")
        print(f"✓ Found {len(result['links'])} links")
    else:
        print("✗ Failed to fetch page")

if __name__ == "__main__":
    asyncio.run(test())
