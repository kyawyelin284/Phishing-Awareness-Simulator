#!/usr/bin/env python3
"""
Phishing Awareness Simulator - Main Entry Point

A defensive cybersecurity tool that analyzes webpages for phishing characteristics.
This tool is designed for educational and awareness purposes only.
"""

import sys
import argparse
from urllib.parse import urlparse

# Import all our modules
from fetcher import fetch_html
from parser import (
    extract_forms, extract_external_resources, extract_page_title
)
from domain_checks import check_suspicious_domain
from form_checks import detect_login_form, check_form_action
from content_checks import check_brand_mismatch, analyze_suspicious_content, check_https_usage
from scorer import calculate_risk_score, analyze_external_resources, generate_summary_report
from utils import is_valid_url, normalize_url, extract_domain_from_url


def analyze_webpage(url: str) -> str:
    """
    Main analysis function that coordinates all phishing detection modules.
    
    Args:
        url: URL to analyze
        
    Returns:
        Analysis report string
    """
    # Validate and normalize URL
    if not is_valid_url(url):
        return "❌ Error: Invalid URL format"
    
    normalized_url = normalize_url(url)
    
    print(f"🔍 Analyzing: {normalized_url}")
    print("⏳ Fetching webpage...")
    
    # Fetch HTML
    html_content = fetch_html(normalized_url)
    if not html_content:
        return "❌ Error: Failed to fetch webpage content"
    
    print("✅ Webpage fetched successfully")
    print("🔍 Analyzing content...")
    
    # Parse HTML (import here to avoid dependency if fetch fails)
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
    except ImportError:
        return "❌ Error: BeautifulSoup4 is required. Install with: pip install beautifulsoup4"
    
    # Extract domain information
    domain = extract_domain_from_url(normalized_url)
    base_domain = domain.split(':')[0]  # Remove port if present
    
    # Parse page elements
    page_title = extract_page_title(soup)
    forms = extract_forms(soup)
    external_resources = extract_external_resources(soup, base_domain)
    
    print(f"📊 Found {len(forms)} forms and {len(external_resources)} external resources")
    
    # Run phishing detection checks
    print("🛡️ Running security checks...")
    
    # 1. Domain analysis
    domain_result = check_suspicious_domain(domain)
    
    # 2. Login form detection
    login_result = detect_login_form(forms)
    
    # 3. Form action analysis
    form_action_result = check_form_action(forms, base_domain)
    
    # 4. Brand mismatch detection
    brand_result = check_brand_mismatch(page_title, domain)
    
    # 5. Content analysis
    content_result = analyze_suspicious_content(page_title)
    
    # 6. HTTPS usage check
    https_result = check_https_usage(normalized_url, forms)
    
    # 7. External resources analysis
    external_resources_result = analyze_external_resources(external_resources)
    
    # Combine HTTPS result with content result
    if https_result["score"] > 0:
        content_result["score"] += https_result["score"]
        content_result["reasons"].extend(https_result["reasons"])
        if https_result["score"] > 0 and not content_result["flag"]:
            content_result["flag"] = True
    
    print("📈 Calculating risk score...")
    
    # Calculate final risk score
    analysis_results = calculate_risk_score(
        domain_result,
        login_result,
        form_action_result,
        brand_result,
        content_result,
        external_resources_result
    )
    
    # Generate report
    report = generate_summary_report(analysis_results, normalized_url)
    
    return report


def main():
    """
    Main function that handles command line arguments and runs analysis.
    """
    parser = argparse.ArgumentParser(
        description="Phishing Awareness Simulator - Detect phishing characteristics in webpages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detector.py https://example.com
  python detector.py https://suspicious-login.xyz
  python detector.py --verbose https://paypal-secure.com

This tool is for educational and defensive cybersecurity purposes only.
        """
    )
    
    parser.add_argument(
        'url',
        help='URL to analyze for phishing characteristics'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output with detailed analysis steps'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Phishing Awareness Simulator v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Show disclaimer
    print("🛡️  Phishing Awareness Simulator v1.0.0")
    print("⚠️  For educational and defensive purposes only")
    print("=" * 50)
    
    try:
        # Run analysis
        report = analyze_webpage(args.url)
        
        # Print report
        print("\n" + "=" * 50)
        print(report)
        print("=" * 50)
        
        # Return exit code based on risk level
        if "LIKELY PHISHING" in report:
            sys.exit(2)  # High risk
        elif "SUSPICIOUS" in report:
            sys.exit(1)  # Medium risk
        else:
            sys.exit(0)  # Low risk
            
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()