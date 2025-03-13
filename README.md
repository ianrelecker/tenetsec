<div align="center">
  <h1>TenetSec</h1>
  <p><strong>Advanced Security Assessment Tool for Microsoft 365 Tenants</strong></p>
  <p>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
    <img src="https://img.shields.io/badge/Python-3.8+-brightgreen.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/Platform-Cross--platform-lightgrey.svg" alt="Platform">
  </p>
</div>

## 🔒 Overview

TenetSec is a comprehensive security assessment tool that identifies vulnerabilities and security misconfigurations in Microsoft 365 environments. Using Microsoft Graph APIs, it analyzes your tenant's security settings across multiple services and provides actionable remediation guidance with prioritized recommendations.

## ✨ Key Features

- **Comprehensive Security Analysis** - Evaluates security configurations across all major M365 services
- **AI-Powered Recommendations** - Provides detailed, contextual remediation steps using anonymized data
- **Multi-format Reporting** - Generates console, HTML, and JSON reports with visual indicators
- **Prioritized Findings** - Categorizes issues by severity and business impact
- **Detailed Remediation Guidance** - Includes exact navigation paths and commands for fixes
- **Privacy-Focused** - All API integration uses robust anonymization to protect sensitive tenant data
- **Modern Graph API Integration** - Uses the latest Microsoft Graph APIs for reliable assessments
- **Customizable Assessment Rules** - Add or modify security checks based on your requirements

## 📊 Assessment Areas

TenetSec evaluates security across all major Microsoft 365 services:

- **Identity** - MFA, Conditional Access, privileged roles, password policies, external access
- **Defender for Office 365** - Safe Attachments, Safe Links, anti-phishing, zero-hour auto purge
- **Exchange Online** - Email authentication, mailbox security, transport rules, client settings
- **SharePoint & OneDrive** - Sharing settings, access controls, data protection, device management
- **Teams** - External access, guest permissions, meeting policies, app governance

## 🚀 Quick Start

1. Clone this repository
2. Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Set up your Azure AD App registration
5. Configure your credentials using either:
   - `config.json` file: `cp config.json.example config.json` and edit with your credentials, or
   - `.env` file: `cp .env.example .env` and edit with your credentials
6. (Optional) Configure AI API settings:
   - In config.json, provide your AI API key and endpoint, or
   - Set environment variables: `TENETSEC_AI_API_KEY`, `TENETSEC_AI_API_ENDPOINT`, and `TENETSEC_AI_API_MODEL`
7. Run the assessment: `python -m tenetsec.main`

## 📋 Sample Output

TenetSec provides detailed assessment results in multiple formats:

### Console Output
```
TenetSec Security Assessment Report for Contoso Inc.

Summary
Date: 2025-03-13_14-30-22
Tenant ID: a1b2c3d4-e5f6-7890-abcd-1234567890ab
Total Checks: 85
Pass Rate: 72.9% (62 passed, 23 failed)

Results by Severity
┌──────────┬───────┬────────┬────────┬──────────┐
│ Severity │ Total │ Passed │ Failed │ Pass Rate│
├──────────┼───────┼────────┼────────┼──────────┤
│ CRITICAL │ 12    │ 7      │ 5      │ 58.3%    │
│ HIGH     │ 23    │ 16     │ 7      │ 69.6%    │
│ MEDIUM   │ 31    │ 24     │ 7      │ 77.4%    │
│ LOW      │ 14    │ 12     │ 2      │ 85.7%    │
│ INFO     │ 5     │ 3      │ 2      │ 60.0%    │
└──────────┴───────┴────────┴────────┴──────────┘
```

### HTML Report

The HTML report includes:
- Interactive charts and visualizations
- Tabbed interface for all assessment areas
- Color-coded severity indicators
- Detailed findings with context and remediation steps
- AI-powered recommendations section with implementation guidance

### AI Recommendations

Each AI recommendation includes:
- Detailed explanation of the security risk
- Step-by-step implementation instructions
- Effort level required (Low/Medium/High)
- Security impact (Low/Medium/High)
- References to specific security findings

## 📚 Documentation

See the [docs](./docs/) folder for detailed documentation:

- [Setup Guide](./docs/setup.md) - Installation and configuration instructions
- [Usage Guide](./docs/usage.md) - How to use TenetSec effectively
- [Concepts](./docs/concepts.md) - Architecture and design concepts
- [AI Recommendations](./docs/ai_recommendations.md) - How the AI recommendation engine works

## 🔧 Advanced Usage

TenetSec supports various command-line options:

```bash
# Run specific assessments
python -m tenetsec.main --assessment identity defender

# Generate only HTML report
python -m tenetsec.main --format html

# Specify output directory
python -m tenetsec.main --output-dir /path/to/reports

# Enable debug logging
python -m tenetsec.main --debug
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
