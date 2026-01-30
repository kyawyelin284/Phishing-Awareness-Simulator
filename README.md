# Phishing Awareness Simulator

A defensive cybersecurity tool that analyzes webpages for phishing characteristics. This tool is designed for educational and awareness purposes only.

## Features

- 🔍 **Domain Analysis**: Detects suspicious domains, typosquatting, and homograph attacks
- 📝 **Form Detection**: Identifies login forms and analyzes their submission endpoints
- 🏢 **Brand Mismatch Detection**: Checks for mismatches between page content and domain
- 🔗 **External Resource Analysis**: Monitors external scripts, stylesheets, and iframes
- 📊 **Risk Scoring**: Comprehensive risk assessment with detailed findings
- 🛡️ **Security-Focused**: Read-only analysis, never submits forms or interacts maliciously

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd "Phishing Awareness Simulator"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests beautifulsoup4 tldextract
```

## Usage

### Basic Usage
```bash
python phishing_detector/detector.py https://example.com
```

### Examples
```bash
# Analyze a suspicious login page
python phishing_detector/detector.py https://suspicious-login.xyz

# Analyze a legitimate site
python phishing_detector/detector.py https://github.com

# Enable verbose output
python phishing_detector/detector.py --verbose https://example.com
```

### Command Line Options
- `--verbose, -v`: Enable verbose output with detailed analysis steps
- `--version`: Show version information
- `--help`: Show help message

## Output

The tool provides a comprehensive analysis report with:

- **Risk Score** (0-100)
- **Risk Level** (Low Risk, Suspicious, or Likely Phishing)
- **Detailed Findings** with specific security concerns
- **Risk Breakdown** showing points from each analysis module

### Example Output
```
🔍 Phishing Analysis Report
Target URL: https://example-login.xyz

🚨 Form submits to external domain: steal-data.ru
⚠️ Login form requesting password found
⚠️ Suspicious domain structure detected
⚠️ Page title claims brand "PayPal" but domain mismatch

🔥 Risk Score: 82/100
🚨 Verdict: LIKELY PHISHING PAGE

📊 Risk Breakdown:
  • Suspicious domain: 25 points
  • Login form detected: 15 points
  • External form submission: 35 points
  • Brand/domain mismatch: 20 points
```

## Architecture

The tool is modular with the following components:

- `detector.py` - Main entry point and CLI interface
- `fetcher.py` - Safe webpage HTML fetching
- `parser.py` - HTML parsing and element extraction
- `domain_checks.py` - Domain and URL analysis
- `form_checks.py` - Login form and action detection
- `content_checks.py` - Brand mismatch and content analysis
- `scorer.py` - Risk scoring and report generation
- `utils.py` - Helper functions and utilities

## Risk Scoring System

| Check | Points Range | Description |
|-------|--------------|-------------|
| Suspicious Domain | 25-35 | Typosquatting, suspicious TLDs, homograph attacks |
| Login Form | 15 | Presence of password fields and login indicators |
| External Form Action | 35-45 | Forms submitting to external domains or IP addresses |
| Brand Mismatch | 20 | Content claims brand but domain doesn't match |
| Suspicious Content | 10-15 | Urgency indicators, fear tactics |
| External Resources | 10-20 | High number of suspicious external resources |

**Risk Levels:**
- **0-30**: Low Risk
- **31-60**: Suspicious
- **61-100**: Likely Phishing

## Security Considerations

⚠️ **Important**: This tool is designed for defensive and educational purposes only. It:

- Never submits forms or sends POST requests
- Uses safe GET requests with timeouts
- Does not interact with web applications maliciously
- Respectfully analyzes publicly available content

## Limitations

- Only analyzes publicly accessible HTML content
- Cannot detect client-side JavaScript redirections
- May have false positives with legitimate security tools
- Analysis is based on heuristics and patterns

## Contributing

This is a defensive security tool. Contributions that enhance detection accuracy, reduce false positives, or improve educational value are welcome.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and cybersecurity awareness purposes only. Users should:
- Only test websites they own or have explicit permission to test
- Use results as indicators, not definitive proof
- Complement with other security analysis tools
- Follow responsible disclosure practices for vulnerabilities found

The authors are not responsible for misuse of this tool.# Phishing-Awareness-Simulator
