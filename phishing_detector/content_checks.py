import re
from typing import Dict, List


def check_brand_mismatch(title: str, domain: str) -> Dict[str, any]:
    """
    Check for brand/domain mismatch - a common phishing indicator.
    
    Args:
        title: Page title text
        domain: Current page domain
        
    Returns:
        Dictionary with mismatch detection results and score
    """
    result = {
        "flag": False,
        "brands_found": [],
        "domain_brands": [],
        "score": 0,
        "reasons": []
    }
    
    if not title or not domain:
        return result
    
    # Popular brands commonly targeted by phishers
    major_brands = {
        'facebook': ['facebook', 'fb', 'meta'],
        'google': ['google', 'gmail', 'gdrive', 'google workspace'],
        'apple': ['apple', 'icloud', 'iphone', 'ipad', 'mac'],
        'microsoft': ['microsoft', 'office', 'outlook', 'teams', 'windows', 'xbox'],
        'amazon': ['amazon', 'aws', 'prime video', 'kindle'],
        'paypal': ['paypal', 'venmo'],
        'instagram': ['instagram', 'insta', 'ig'],
        'twitter': ['twitter', 'x', 'tweet'],
        'linkedin': ['linkedin', 'linked in'],
        'youtube': ['youtube', 'yt', 'you tube'],
        'netflix': ['netflix', 'net flix'],
        'spotify': ['spotify', 'spot ify'],
        'dropbox': ['dropbox', 'drop box'],
        'github': ['github', 'git hub'],
        'steam': ['steam'],
        'ebay': ['ebay', 'e bay'],
        'walmart': ['walmart', 'wal mart'],
        'target': ['target'],
        'bestbuy': ['best buy', 'bestbuy'],
        'bank of america': ['bank of america', 'bofa'],
        'chase': ['chase', 'jpmorgan'],
        'wells fargo': ['wells fargo'],
        'citibank': ['citibank', 'citi'],
        'capital one': ['capital one', 'capitol one']
    }
    
    title_lower = title.lower()
    domain_lower = domain.lower()
    
    # Find brands mentioned in title
    for brand_name, brand_variants in major_brands.items():
        for variant in brand_variants:
            if re.search(r'\b' + re.escape(variant) + r'\b', title_lower):
                if brand_name not in result["brands_found"]:
                    result["brands_found"].append(brand_name)
    
    # Find brands mentioned in domain
    for brand_name, brand_variants in major_brands.items():
        for variant in brand_variants:
            if re.search(re.escape(variant), domain_lower):
                if brand_name not in result["domain_brands"]:
                    result["domain_brands"].append(brand_name)
    
    # Check for mismatch
    if result["brands_found"] and not result["domain_brands"]:
        result["flag"] = True
        result["score"] = 20
        result["reasons"].append(f"Title mentions brands {result['brands_found']} but domain doesn't contain any")
    
    elif result["brands_found"] and result["domain_brands"]:
        # Check if the brands in title match those in domain
        title_brands_set = set(result["brands_found"])
        domain_brands_set = set(result["domain_brands"])
        
        # If no overlap, it's suspicious
        if not title_brands_set.intersection(domain_brands_set):
            result["flag"] = True
            result["score"] = 15
            result["reasons"].append(
                f"Brand mismatch: Title mentions {result['brands_found']} "
                f"but domain mentions {result['domain_brands']}"
            )
    
    return result


def analyze_suspicious_content(title: str, meta_description: str = "") -> Dict[str, any]:
    """
    Analyze page content for suspicious patterns.
    
    Args:
        title: Page title
        meta_description: Meta description (optional)
        
    Returns:
        Dictionary with content analysis results
    """
    result = {
        "flag": False,
        "suspicious_phrases": [],
        "urgency_indicators": [],
        "score": 0,
        "reasons": []
    }
    
    content_to_check = f"{title} {meta_description}".lower()
    
    # Suspicious phrases often used in phishing
    suspicious_phrases = [
        "verify your account",
        "suspended account",
        "account locked",
        "security alert",
        "unusual activity",
        "verify identity",
        "confirm your identity",
        "update payment",
        "billing issue",
        "expiration notice",
        "limited time offer",
        "act now",
        "immediate action required",
        "click here immediately",
        "urgent notification",
        "security verification"
    ]
    
    for phrase in suspicious_phrases:
        if phrase in content_to_check:
            result["suspicious_phrases"].append(phrase)
            result["flag"] = True
            result["score"] += 5
    
    # Urgency and fear indicators
    urgency_words = [
        "urgent", "immediate", "critical", "alert", "warning",
        "suspended", "blocked", "terminated", "expired", "deadline",
        "limited", "offer expires", "act now", "hurry", "fast"
    ]
    
    for word in urgency_words:
        if f" {word} " in f" {content_to_check} " or content_to_check.startswith(word + " ") or content_to_check.endswith(" " + word):
            result["urgency_indicators"].append(word)
            result["score"] += 2
    
    # Cap the score for this module
    result["score"] = min(result["score"], 15)
    
    if result["flag"]:
        if result["suspicious_phrases"]:
            result["reasons"].append(f"Found suspicious phrases: {result['suspicious_phrases'][:3]}")
        if result["urgency_indicators"]:
            result["reasons"].append(f"Found urgency indicators: {result['urgency_indicators'][:5]}")
    
    return result


def extract_meta_tags(soup) -> Dict[str, str]:
    """
    Extract important meta tags from the page.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        Dictionary with meta tag content
    """
    meta_data = {
        "description": "",
        "keywords": "",
        "author": "",
        "robots": ""
    }
    
    # Description
    desc_tag = soup.find('meta', attrs={'name': 'description'})
    if desc_tag:
        meta_data["description"] = desc_tag.get('content', '').strip()
    
    # Keywords
    keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
    if keywords_tag:
        meta_data["keywords"] = keywords_tag.get('content', '').strip()
    
    # Author
    author_tag = soup.find('meta', attrs={'name': 'author'})
    if author_tag:
        meta_data["author"] = author_tag.get('content', '').strip()
    
    # Robots
    robots_tag = soup.find('meta', attrs={'name': 'robots'})
    if robots_tag:
        meta_data["robots"] = robots_tag.get('content', '').strip()
    
    return meta_data


def check_https_usage(page_url: str, forms: List[Dict]) -> Dict[str, any]:
    """
    Check for HTTPS inconsistencies.
    
    Args:
        page_url: The URL of the page
        forms: List of forms on the page
        
    Returns:
        Dictionary with HTTPS analysis results
    """
    result = {
        "is_https": page_url.startswith('https://'),
        "insecure_forms": 0,
        "mixed_content": False,
        "score": 0,
        "reasons": []
    }
    
    # Check if page is HTTPS but has HTTP form actions
    if result["is_https"]:
        for form in forms:
            action = form.get('action', '')
            if action.startswith('http://'):
                result["insecure_forms"] += 1
                result["mixed_content"] = True
                result["score"] += 10
        
        if result["mixed_content"]:
            result["reasons"].append(f"HTTPS page contains {result['insecure_forms']} insecure HTTP form(s)")
    
    else:
        # HTTP page is less trustworthy
        result["score"] = 5
        result["reasons"].append("Page is served over insecure HTTP")
    
    return result