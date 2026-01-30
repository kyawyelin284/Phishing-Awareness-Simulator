import re
import tldextract
from typing import Dict, List


def check_suspicious_domain(domain: str) -> Dict:
    """
    Check for suspicious domain characteristics.
    
    Args:
        domain: Domain string to analyze
        
    Returns:
        Dictionary with flag, reasons, and score
    """
    result = {
        "flag": False,
        "reasons": [],
        "score": 0
    }
    
    if not domain:
        return result
    
    domain_lower = domain.lower()
    extracted = tldextract.extract(domain_lower)
    
    # Extract main domain parts
    subdomain = extracted.subdomain
    main_domain = extracted.domain
    suffix = extracted.suffix
    
    # Check for leetspeak/number substitutions
    if has_number_substitutions(main_domain):
        result["flag"] = True
        result["reasons"].append("Domain contains number substitutions (leetspeak)")
        result["score"] += 10
    
    # Check for phishing keywords in domain
    phishing_keywords = [
        'login', 'verify', 'secure', 'account', 'update', 'bank',
        'signin', 'auth', 'payment', 'wallet', 'support', 'service',
        'confirm', 'recover', 'access', 'identity', 'official'
    ]
    
    for keyword in phishing_keywords:
        if keyword in main_domain or keyword in subdomain:
            result["flag"] = True
            result["reasons"].append(f"Domain contains phishing keyword: '{keyword}'")
            result["score"] += 8
            break
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.tk', '.ru', '.cn', '.ml', '.ga', '.cf']
    if suffix in suspicious_tlds:
        result["flag"] = True
        result["reasons"].append(f"Domain uses suspicious TLD: .{suffix}")
        result["score"] += 12
    
    # Check for excessively long domain
    if len(main_domain) > 15:
        result["flag"] = True
        result["reasons"].append(f"Domain name is unusually long: {len(main_domain)} characters")
        result["score"] += 8
    
    # Check for too many hyphens
    if main_domain.count('-') > 2 or subdomain.count('-') > 3:
        result["flag"] = True
        result["reasons"].append("Domain contains excessive hyphens")
        result["score"] += 10
    
    # Check for homograph attacks (similar looking characters)
    if has_homograph_chars(main_domain):
        result["flag"] = True
        result["reasons"].append("Domain may contain homograph characters")
        result["score"] += 15
    
    # Check for IP address as domain
    if is_ip_address(domain):
        result["flag"] = True
        result["reasons"].append("Domain is an IP address")
        result["score"] += 20
    
    # Check for lookalike domains of popular brands
    popular_brands = [
        'facebook', 'google', 'apple', 'microsoft', 'amazon', 'paypal',
        'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'spotify',
        'dropbox', 'github', 'steam', 'ebay', 'walmart', 'target', 'bestbuy'
    ]
    
    for brand in popular_brands:
        if is_lookalike_domain(main_domain, brand):
            result["flag"] = True
            result["reasons"].append(f"Domain appears to mimic brand: {brand}")
            result["score"] += 25
            break
    
    # Ensure score doesn't exceed max
    result["score"] = min(result["score"], 35)
    
    return result


def has_number_substitutions(domain: str) -> bool:
    """Check if domain uses numbers to replace letters."""
    substitutions = {
        '0': 'o', '1': 'l', '1': 'i', '3': 'e', '4': 'a', 
        '5': 's', '7': 't', '8': 'b'
    }
    
    # Simple check: if domain has both letters and numbers mixed in suspicious patterns
    return bool(re.search(r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', domain))


def has_homograph_chars(domain: str) -> bool:
    """Check for potentially suspicious Unicode characters."""
    # Common homograph characters that look like ASCII
    homograph_chars = [
        'а', 'с', 'е', 'о', 'р', 'х', 'у',  # Cyrillic
        'ａ', 'ｂ', 'ｃ', 'ｄ', 'ｅ', 'ｆ', 'ｇ', 'ｈ', 'ｉ', 'ｊ', 'ｋ', 'ｌ', 'ｍ',  # Full-width
    ]
    
    for char in homograph_chars:
        if char in domain:
            return True
    
    # Check for non-ASCII characters
    try:
        domain.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True


def is_ip_address(domain: str) -> bool:
    """Check if the domain is actually an IP address."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, domain))


def is_lookalike_domain(domain: str, brand: str) -> bool:
    """Check if domain is trying to look like a brand domain."""
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    
    # Direct match (shouldn't happen for lookalikes)
    if brand_lower in domain_lower:
        # Check if it's the actual brand domain or a lookalike
        # Look for common typosquatting patterns
        if domain_lower != brand_lower:
            return True
    
    return False


def extract_main_domain(full_domain: str) -> str:
    """Extract the main domain without subdomains."""
    extracted = tldextract.extract(full_domain.lower())
    return f"{extracted.domain}.{extracted.suffix}" if extracted.domain else ""