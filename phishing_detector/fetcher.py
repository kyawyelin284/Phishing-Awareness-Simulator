import requests
from urllib.parse import urlparse
from typing import Optional


def fetch_html(url: str) -> Optional[str]:
    """
    Safely fetch HTML content from a URL.
    
    Args:
        url: The URL to fetch
        
    Returns:
        Raw HTML string or None if error occurs
    """
    try:
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print("❌ Invalid URL format")
            return None
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )
        
        response.raise_for_status()
        
        # Only accept HTML content
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' not in content_type:
            print("⚠️ URL does not return HTML content")
            return None
            
        return response.text
        
    except requests.exceptions.Timeout:
        print("⏱️ Request timeout (10 seconds)")
        return None
    except requests.exceptions.ConnectionError:
        print("🔌 Connection error - unable to reach the server")
        return None
    except requests.exceptions.TooManyRedirects:
        print("🔄 Too many redirects")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"🚫 HTTP error: {e.response.status_code}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None