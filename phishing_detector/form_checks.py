from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any


def detect_login_form(forms: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect if forms contain login-related fields.
    
    Args:
        forms: List of form dictionaries
        
    Returns:
        Dictionary with detection results and score
    """
    result = {
        "flag": False,
        "login_forms": [],
        "score": 0,
        "reasons": []
    }
    
    for i, form in enumerate(forms):
        form_analysis = {
            "form_index": i,
            "has_password": False,
            "suspicious_fields": [],
            "risk_score": 0
        }
        
        # Check for password field
        for input_field in form.get('inputs', []):
            input_type = input_field.get('type', '').lower()
            input_name = input_field.get('name', '').lower()
            input_id = input_field.get('id', '').lower()
            
            # Password field detection
            if input_type == 'password':
                form_analysis["has_password"] = True
                form_analysis["risk_score"] += 10
            
            # Check for suspicious field names
            suspicious_field_patterns = [
                'email', 'user', 'login', 'username', 'userid', 'user_id',
                'password', 'pass', 'passwd', 'pwd', 'card', 'cardnumber',
                'cc', 'cvv', 'cvc', 'otp', 'token', 'ssn', 'social'
            ]
            
            for pattern in suspicious_field_patterns:
                if pattern in input_name or pattern in input_id:
                    if pattern not in [f['pattern'] for f in form_analysis["suspicious_fields"]]:
                        form_analysis["suspicious_fields"].append({
                            "pattern": pattern,
                            "name": input_field.get('name', ''),
                            "type": input_type,
                            "id": input_field.get('id', '')
                        })
                        form_analysis["risk_score"] += 3
        
        # Determine if this is a login form
        if form_analysis["has_password"] or len(form_analysis["suspicious_fields"]) >= 2:
            form_analysis["is_login"] = True
            result["flag"] = True
            result["login_forms"].append(form_analysis)
            result["score"] += min(form_analysis["risk_score"], 15)
    
    if result["flag"]:
        result["reasons"].append(f"Found {len(result['login_forms'])} potential login form(s)")
    
    return result


def check_form_action(forms: List[Dict[str, Any]], page_domain: str) -> Dict[str, Any]:
    """
    Check if forms submit to external domains (critical phishing indicator).
    
    Args:
        forms: List of form dictionaries
        page_domain: Domain of the current page
        
    Returns:
        Dictionary with external action analysis and score
    """
    result = {
        "flag": False,
        "external_actions": [],
        "score": 0,
        "reasons": []
    }
    
    for i, form in enumerate(forms):
        action = form.get('action', '').strip()
        if not action:
            continue
            
        # Skip if it's just a fragment or relative path
        if action.startswith('#') or action.startswith('javascript:'):
            continue
            
        # Resolve relative URLs
        if action.startswith('/'):
            full_action = f"https://{page_domain}{action}"
        elif not action.startswith(('http://', 'https://')):
            full_action = f"https://{page_domain}/{action}"
        else:
            full_action = action
            
        try:
            parsed_action = urlparse(full_action)
            action_domain = parsed_action.netloc.lower()
            
            # Check if action points to different domain
            if action_domain and action_domain != page_domain.lower():
                external_analysis = {
                    "form_index": i,
                    "action_url": full_action,
                    "action_domain": action_domain,
                    "is_http": parsed_action.scheme == 'http',
                    "is_ip": is_ip_address(action_domain),
                    "risk_score": 0
                }
                
                # High risk for IP addresses
                if external_analysis["is_ip"]:
                    external_analysis["risk_score"] += 20
                    result["reasons"].append(f"Form {i} submits to IP address: {action_domain}")
                
                # Medium risk for HTTP on HTTPS page
                if external_analysis["is_http"]:
                    external_analysis["risk_score"] += 15
                    result["reasons"].append(f"Form {i} uses insecure HTTP submission")
                
                # High risk for external domain
                external_analysis["risk_score"] += 25
                result["reasons"].append(f"Form {i} submits to external domain: {action_domain}")
                
                result["external_actions"].append(external_analysis)
                result["flag"] = True
                result["score"] += min(external_analysis["risk_score"], 45)
                
        except Exception as e:
            # Malformed URL is also suspicious
            result["flag"] = True
            result["score"] += 10
            result["reasons"].append(f"Form {i} has malformed action URL: {action}")
    
    return result


def is_ip_address(domain: str) -> bool:
    """Check if the domain is actually an IP address."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    return bool(re.match(ip_pattern, domain))


def analyze_form_methods(forms: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze form methods for suspicious patterns.
    
    Args:
        forms: List of form dictionaries
        
    Returns:
        Dictionary with method analysis
    """
    result = {
        "post_forms": 0,
        "get_forms": 0,
        "no_method_forms": 0,
        "suspicious_get_forms": []
    }
    
    for i, form in enumerate(forms):
        method = form.get('method', 'get').lower()
        
        if method == 'post':
            result["post_forms"] += 1
        elif method == 'get':
            result["get_forms"] += 1
            
            # GET method for sensitive forms is suspicious
            has_sensitive_fields = False
            for input_field in form.get('inputs', []):
                input_name = input_field.get('name', '').lower()
                input_type = input_field.get('type', '').lower()
                
                if input_type == 'password' or any(keyword in input_name for keyword in ['password', 'pass', 'card', 'ssn']):
                    has_sensitive_fields = True
                    break
            
            if has_sensitive_fields:
                result["suspicious_get_forms"].append(i)
        else:
            result["no_method_forms"] += 1
    
    return result