from bs4 import BeautifulSoup, Tag
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any


def extract_forms(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """
    Extract all form elements from the page.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of form dictionaries with action, method, and inputs
    """
    forms = []
    
    for form in soup.find_all('form'):
        if isinstance(form, Tag):
            form_data = {
                'action': str(form.get('action', '')),
                'method': str(form.get('method', 'get')).lower(),
                'inputs': extract_inputs(form)
            }
            forms.append(form_data)
    
    return forms


def extract_inputs(form: Tag) -> List[Dict[str, str]]:
    """
    Extract all input fields from a form.
    
    Args:
        form: BeautifulSoup form element
        
    Returns:
        List of input dictionaries with type, name, and id
    """
    inputs = []
    
    for input_elem in form.find_all(['input', 'textarea', 'select']):
        if isinstance(input_elem, Tag):
            input_data = {
                'type': str(input_elem.get('type', 'text')),
                'name': str(input_elem.get('name', '')),
                'id': str(input_elem.get('id', '')),
                'tag': str(input_elem.name)
            }
            inputs.append(input_data)
    
    return inputs


def extract_external_resources(soup: BeautifulSoup, base_domain: str) -> List[Dict[str, str]]:
    """
    Extract external resources loaded from different domains.
    
    Args:
        soup: BeautifulSoup object
        base_domain: Base domain of the current page
        
    Returns:
        List of external resources with type and URL
    """
    external_resources = []
    
    # Check script tags
    for script in soup.find_all('script'):
        if isinstance(script, Tag) and script.has_attr('src'):
            src = str(script['src'])
            if is_external_url(src, base_domain):
                external_resources.append({
                    'type': 'script',
                    'url': src,
                    'domain': extract_domain_from_url(src)
                })
    
    # Check iframe tags
    for iframe in soup.find_all('iframe'):
        if isinstance(iframe, Tag) and iframe.has_attr('src'):
            src = str(iframe['src'])
            if is_external_url(src, base_domain):
                external_resources.append({
                    'type': 'iframe',
                    'url': src,
                    'domain': extract_domain_from_url(src)
                })
    
    # Check CSS link tags
    for link in soup.find_all('link'):
        if (isinstance(link, Tag) and link.has_attr('href') and 
            link.has_attr('rel') and 'stylesheet' in str(link.get('rel'))):
            href = str(link['href'])
            if is_external_url(href, base_domain):
                external_resources.append({
                    'type': 'css',
                    'url': href,
                    'domain': extract_domain_from_url(href)
                })
    
    # Check image tags (optional, usually lower risk)
    for img in soup.find_all('img'):
        if isinstance(img, Tag) and img.has_attr('src'):
            src = str(img['src'])
            if is_external_url(src, base_domain):
                external_resources.append({
                    'type': 'image',
                    'url': src,
                    'domain': extract_domain_from_url(src)
                })
    
    return external_resources


def extract_page_title(soup: BeautifulSoup) -> str:
    """
    Extract the page title.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        Page title string
    """
    title_tag = soup.find('title')
    return title_tag.get_text().strip() if title_tag else ''


def is_external_url(url: str, base_domain: str) -> bool:
    """
    Check if a URL points to an external domain.
    
    Args:
        url: URL to check
        base_domain: Base domain to compare against
        
    Returns:
        True if URL is external, False otherwise
    """
    try:
        parsed = urlparse(url)
        # Relative URLs are not external
        if not parsed.netloc:
            return False
        return parsed.netloc.lower() != base_domain.lower()
    except Exception:
        return True


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from a URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain string
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ''