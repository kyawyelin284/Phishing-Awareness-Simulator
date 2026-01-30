from typing import Dict, List, Any


def calculate_risk_score(
    domain_result: Dict[str, Any],
    login_result: Dict[str, Any],
    form_action_result: Dict[str, Any],
    brand_result: Dict[str, Any],
    content_result: Dict[str, Any],
    external_resources_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculate final risk score based on all analysis results.
    
    Args:
        domain_result: Domain analysis results
        login_result: Login form analysis results
        form_action_result: Form action analysis results
        brand_result: Brand mismatch analysis results
        content_result: Content analysis results
        external_resources_result: External resources analysis results
        
    Returns:
        Dictionary with total score, risk level, and findings
    """
    total_score = 0
    findings = []
    
    # Add domain analysis score
    if domain_result.get("flag", False):
        domain_score = domain_result.get("score", 0)
        total_score += domain_score
        findings.extend(domain_result.get("reasons", []))
    
    # Add login form analysis score
    if login_result.get("flag", False):
        login_score = login_result.get("score", 0)
        total_score += login_score
        findings.extend(login_result.get("reasons", []))
    
    # Add form action analysis score (critical indicator)
    if form_action_result.get("flag", False):
        form_score = form_action_result.get("score", 0)
        total_score += form_score
        findings.extend(form_action_result.get("reasons", []))
    
    # Add brand mismatch analysis score
    if brand_result.get("flag", False):
        brand_score = brand_result.get("score", 0)
        total_score += brand_score
        findings.extend(brand_result.get("reasons", []))
    
    # Add content analysis score
    if content_result.get("flag", False):
        content_score = content_result.get("score", 0)
        total_score += content_score
        findings.extend(content_result.get("reasons", []))
    
    # Add external resources score
    if external_resources_result.get("flag", False):
        external_score = external_resources_result.get("score", 0)
        total_score += external_score
        findings.extend(external_resources_result.get("reasons", []))
    
    # Cap the total score at 100
    total_score = min(total_score, 100)
    
    # Determine risk level
    risk_level = determine_risk_level(total_score)
    
    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "findings": findings,
        "component_scores": {
            "domain": domain_result.get("score", 0),
            "login": login_result.get("score", 0),
            "form_action": form_action_result.get("score", 0),
            "brand": brand_result.get("score", 0),
            "content": content_result.get("score", 0),
            "external_resources": external_resources_result.get("score", 0)
        }
    }


def determine_risk_level(score: int) -> str:
    """
    Determine risk level based on score.
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Risk level string
    """
    if score <= 30:
        return "Low Risk"
    elif score <= 60:
        return "Suspicious"
    else:
        return "Likely Phishing"


def analyze_external_resources(external_resources: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Analyze external resources for suspicious patterns.
    
    Args:
        external_resources: List of external resources
        
    Returns:
        Dictionary with analysis results
    """
    result = {
        "flag": False,
        "total_external": len(external_resources),
        "suspicious_domains": [],
        "score": 0,
        "reasons": []
    }
    
    if not external_resources:
        return result
    
    # Check for suspicious patterns in external domains
    suspicious_patterns = [
        r'.*\.tk$', r'.*\.ml$', r'.*\.ga$', r'.*\.cf$',
        r'.*\.xyz$', r'.*\.top$', r'.*\.ru$', r'.*\.cn$'
    ]
    
    suspicious_domains = set()
    
    for resource in external_resources:
        domain = resource.get("domain", "")
        resource_type = resource.get("type", "")
        
        # Check against suspicious patterns
        for pattern in suspicious_patterns:
            import re
            if re.match(pattern, domain):
                suspicious_domains.add(domain)
        
        # Check for IP addresses
        if is_ip_address(domain):
            suspicious_domains.add(f"{domain} (IP)")
        
        # HTTP resources on HTTPS pages are suspicious
        url = resource.get("url", "")
        if url.startswith("http://"):
            suspicious_domains.add(f"{domain} (HTTP)")
    
    result["suspicious_domains"] = list(suspicious_domains)
    
    # Calculate score based on number of external resources and suspicious domains
    if result["total_external"] > 10:
        result["score"] += 10
        result["reasons"].append(f"High number of external resources: {result['total_external']}")
        result["flag"] = True
    
    if len(result["suspicious_domains"]) > 0:
        result["score"] += min(len(result["suspicious_domains"]) * 5, 10)
        result["reasons"].append(f"Suspicious external domains: {result['suspicious_domains'][:3]}")
        result["flag"] = True
    
    return result


def is_ip_address(domain: str) -> bool:
    """Check if the domain is actually an IP address."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, domain))


def generate_summary_report(analysis_results: Dict[str, Any], url: str) -> str:
    """
    Generate a human-readable summary report.
    
    Args:
        analysis_results: Complete analysis results
        url: The URL that was analyzed
        
    Returns:
        Formatted report string
    """
    score = analysis_results["total_score"]
    risk_level = analysis_results["risk_level"]
    findings = analysis_results["findings"]
    
    report = []
    report.append("🔍 Phishing Analysis Report")
    report.append(f"Target URL: {url}")
    report.append("")
    
    # Key findings
    if findings:
        for finding in findings[:10]:  # Limit to top 10 findings
            if "external domain" in finding.lower() or "ip address" in finding.lower():
                report.append(f"🚨 {finding}")
            elif "login form" in finding.lower() or "password" in finding.lower():
                report.append(f"⚠️ {finding}")
            else:
                report.append(f"⚠️ {finding}")
        report.append("")
    
    # Score and verdict
    report.append(f"🔥 Risk Score: {score}/100")
    
    if risk_level == "Likely Phishing":
        report.append(f"🚨 Verdict: LIKELY PHISHING PAGE")
    elif risk_level == "Suspicious":
        report.append(f"⚠️ Verdict: SUSPICIOUS PAGE")
    else:
        report.append(f"✅ Verdict: LOW RISK PAGE")
    
    report.append("")
    
    # Component breakdown
    components = analysis_results["component_scores"]
    report.append("📊 Risk Breakdown:")
    if components["domain"] > 0:
        report.append(f"  • Suspicious domain: {components['domain']} points")
    if components["login"] > 0:
        report.append(f"  • Login form detected: {components['login']} points")
    if components["form_action"] > 0:
        report.append(f"  • External form submission: {components['form_action']} points")
    if components["brand"] > 0:
        report.append(f"  • Brand/domain mismatch: {components['brand']} points")
    if components["content"] > 0:
        report.append(f"  • Suspicious content: {components['content']} points")
    if components["external_resources"] > 0:
        report.append(f"  • External resources: {components['external_resources']} points")
    
    return "\n".join(report)