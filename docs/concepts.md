# TenetSec Concepts and Architecture

This document explains the core concepts, architecture, and security principles behind TenetSec.

## Core Concepts

### Security Assessment Framework

TenetSec is built on the principle of validating the security configuration of a Microsoft 365 tenant against a set of security best practices. The assessment framework consists of:

1. **Security Modules**: Separate components that assess different aspects of M365 (Identity, Defender, Exchange, etc.)
2. **Security Checks**: Individual tests that validate specific configuration settings or security practices
3. **Severity Levels**: Classification of findings based on their security impact
4. **Recommendations**: Actionable guidance to remediate identified issues

### Microsoft Graph API Integration

TenetSec leverages the Microsoft Graph API to query your M365 tenant's configuration. This provides several benefits:

- **No agent installation required**: Uses standard API access
- **Read-only analysis**: Doesn't modify your tenant
- **Comprehensive coverage**: Access to security settings across all M365 services
- **Modern authentication**: Uses Azure AD App registration and OAuth 2.0

### Report Generation

The reporting system is designed to:
- Provide clear, actionable findings
- Prioritize issues by severity
- Include reference documentation
- Offer multiple output formats (console, JSON, HTML)
- Support tracking improvements over time

## Architecture

TenetSec is built with a modular architecture that separates concerns:

```
┌────────────────┐     ┌──────────────────┐     ┌───────────────┐
│                │     │                  │     │               │
│ Authentication ├────►│ Graph API Client ├────►│ Assessments   │
│                │     │                  │     │               │
└────────────────┘     └──────────────────┘     └───────┬───────┘
                                                        │
                                                        ▼
                                                ┌───────────────┐
                                                │               │
                                                │ Report        │
                                                │ Generation    │
                                                │               │
                                                └───────────────┘
```

### Components

#### 1. Authentication (`auth.py`)

- Manages authentication with the Microsoft Graph API
- Uses MSAL (Microsoft Authentication Library) for OAuth 2.0 flows
- Supports client credentials flow for service applications
- Handles token caching and renewal

#### 2. Graph API Client (`graph_client.py`)

- Provides a consistent interface to the Microsoft Graph API
- Handles API pagination
- Manages request/response formatting
- Deals with error handling and retries

#### 3. Assessment Modules

Base Module (`assessments/base.py`):
- Defines base classes for assessments and check results
- Implements common logic for running checks and aggregating results

Individual Modules:
- `identity.py`: Microsoft Entra ID (Azure AD) assessment
- `defender.py`: Microsoft Defender for Office 365 assessment
- `exchange.py`: Exchange Online assessment
- `sharepoint.py`: SharePoint Online and OneDrive assessment
- `teams.py`: Microsoft Teams assessment

Each module contains specific security checks that target different aspects of the service.

#### 4. Report Generation (`report.py`)

- Aggregates results from all assessments
- Calculates summary statistics
- Generates different report formats
- Visualizes findings with charts and tables

#### 5. Main Application (`main.py`)

- Provides the command line interface
- Coordinates the overall assessment flow
- Handles configuration loading
- Manages execution of assessments and report generation

## Security Principles Evaluated

TenetSec evaluates your M365 tenant's security posture based on the following key principles:

### 1. Identity and Access Management

- **Strong Authentication**: Enforcement of MFA, elimination of legacy authentication
- **Privileged Access Management**: Just-in-time access, role separation, emergency access accounts
- **Access Controls**: Conditional Access policies, risk-based controls, guest user restrictions

### 2. Threat Protection

- **Malware Protection**: Scanning, detection, and prevention for email attachments and links
- **Phishing Protection**: Anti-spoofing, impersonation protection, domain authentication
- **Advanced Detection**: Heuristic scanning, sandboxing, and post-delivery remediation

### 3. Data Protection

- **Information Sharing Controls**: External sharing settings, link permissions, access controls
- **Data Loss Prevention**: Content scanning, sensitive information detection, policy enforcement
- **Device Controls**: Managed device policies, download restrictions, browser-based isolation

### 4. Security Management

- **Auditing and Monitoring**: Logging configuration, alert policies, activity tracking
- **Security Posture Management**: Default security policies, secure defaults, preset configurations
- **Compliance Controls**: Retention policies, information barriers, communication compliance

## Extending TenetSec

TenetSec is designed to be extensible:

### Adding New Security Checks

To add a new security check to an existing module:
1. Add a new method to the appropriate assessment class
2. Register the check in the `_register_checks` method
3. Implement the logic to validate the security setting through the Graph API

### Creating New Assessment Modules

To create an entirely new assessment area:
1. Create a new module file in the `assessments` directory
2. Define a class that inherits from `AssessmentBase`
3. Implement the required checks and register them
4. Add the module to the `ALL_ASSESSMENTS` list in `assessments/__init__.py`

### Custom Report Formats

To add a new report format:
1. Add a new method to the `ReportGenerator` class in `report.py`
2. Implement the logic to format and output the results
3. Update the CLI arguments in `main.py` to support the new format

## Best Practices for Using TenetSec

1. **Run regularly**: Security posture changes over time as settings are modified
2. **Prioritize findings**: Address CRITICAL and HIGH issues first
3. **Document exceptions**: If you can't implement a recommendation due to business requirements, document the exception
4. **Track progress**: Compare results over time to show security improvement
5. **Integrate with workflows**: Automate assessments as part of security governance processes