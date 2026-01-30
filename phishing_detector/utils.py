import re
from urllib.parse import urlparse
from typing import Optional


def is_valid_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from a URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain string or empty string if invalid
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def normalize_url(url: str) -> str:
    """
    Normalize URL by ensuring it has a scheme.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL with scheme
    """
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url


def clean_text(text: str) -> str:
    """
    Clean and normalize text for analysis.
    
    Args:
        text: Text to clean
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def is_ip_address(domain: str) -> bool:
    """
    Check if the domain is actually an IP address.
    
    Args:
        domain: Domain to check
        
    Returns:
        True if it's an IP address, False otherwise
    """
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, domain))


def count_subdomains(domain: str) -> int:
    """
    Count the number of subdomains in a domain.
    
    Args:
        domain: Full domain to analyze
        
    Returns:
        Number of subdomains
    """
    try:
        import tldextract
        extracted = tldextract.extract(domain.lower())
        if extracted.subdomain:
            return len(extracted.subdomain.split('.'))
        return 0
    except Exception:
        # Fallback: count dots excluding the TLD
        parts = domain.split('.')
        if len(parts) > 2:
            return len(parts) - 2
        return 0


def get_base_domain(domain: str) -> str:
    """
    Extract the base domain without subdomains.
    
    Args:
        domain: Full domain
        
    Returns:
        Base domain
    """
    try:
        import tldextract
        extracted = tldextract.extract(domain.lower())
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return domain
    except Exception:
        # Fallback: get last two parts
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain


def contains_suspicious_patterns(text: str, patterns: list) -> bool:
    """
    Check if text contains any of the suspicious patterns.
    
    Args:
        text: Text to check
        patterns: List of patterns to search for
        
    Returns:
        True if any pattern is found, False otherwise
    """
    text_lower = text.lower()
    for pattern in patterns:
        if pattern in text_lower:
            return True
    return False


def calculate_domain_entropy(domain: str) -> float:
    """
    Calculate the entropy of a domain name.
    Higher entropy may indicate random/dga domains.
    
    Args:
        domain: Domain to analyze
        
    Returns:
        Entropy value
    """
    if not domain:
        return 0.0
    
    import math
    import collections
    
    # Count character frequencies
    counter = collections.Counter(domain)
    length = len(domain)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe file system usage.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    
    # Ensure it's not empty
    if not sanitized:
        sanitized = "untitled"
    
    return sanitized[:255]  # Limit length