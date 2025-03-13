# TenetSec Setup Guide

This guide will help you set up and configure TenetSec to run against your Microsoft 365 tenant.

## Prerequisites

- Python 3.8 or higher
- A Microsoft 365 tenant
- Global Administrator access or similar high-level permissions to your M365 tenant
- Basic familiarity with Azure Active Directory

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/tenetsec.git
cd tenetsec
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Or, install the package in development mode:

```bash
pip install -e .
```

Note: If you're on macOS or using a system with an externally managed Python installation, you must use a virtual environment.

## Setting up Azure AD App Registration

Before you can use TenetSec, you need to register an application in Azure AD to access the Microsoft Graph API:

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations** > **New registration**
3. Enter a name for your application (e.g., "TenetSec")
4. Select **Accounts in this organizational directory only** as the supported account type
5. Click **Register**

### Configuring API permissions

1. In your newly created app registration, navigate to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Application permissions**
5. Add the following permissions:
   - Organization.Read.All
   - Directory.Read.All
   - SecurityEvents.Read.All
   - Policy.Read.All
   - RoleManagement.Read.Directory
   - User.Read.All
   - Domain.Read.All
   - Group.Read.All
   - ThreatIndicators.Read.All
   - AuditLog.Read.All
   - Sites.Read.All
   - TeamSettings.Read.All
   - TeamMember.Read.All
   - Report.Read.All
   - SecurityActions.Read.All
   - IdentityRiskyUser.Read.All
   - DelegatedPermissionGrant.Read.All
   - Mail.Read
   - Mail.ReadBasic.All
   - MailboxSettings.Read
   - IdentityProvider.Read.All
   - ConditionalAccess.Read.All
   - Application.Read.All

6. Click **Add permissions**
7. Click **Grant admin consent for (your tenant)** and confirm

### Creating a client secret

1. In your app registration, navigate to **Certificates & secrets**
2. Under **Client secrets**, click **New client secret**
3. Add a description and select an expiration period
4. Click **Add**
5. **Important**: Copy the generated secret value immediately. You won't be able to see it again!

## Configuration

You can configure TenetSec using either a JSON config file or environment variables.

### Option 1: JSON Configuration File

1. Create a configuration file by copying the example:

```bash
cp config.json.example config.json
```

2. Edit the `config.json` file with your tenant ID, client ID(application ID), and client secret:

```json
{
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scopes": [
    "https://graph.microsoft.com/.default"
  ],
  
  "ai_recommendations": {
    "enabled": true,
    "api_key": "your-ai-api-key",
    "api_endpoint": "https://api.openai.com/v1/chat/completions",
    "api_model": "gpt-4"
  }
}
```

### Option 2: Environment Variables

1. Create a `.env` file by copying the example:

```bash
cp .env.example .env
```

2. Edit the `.env` file with your tenant ID, client ID, and client secret:

```
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# AI API Configuration (Optional)
TENETSEC_AI_API_KEY=your-ai-api-key
TENETSEC_AI_API_ENDPOINT=https://api.openai.com/v1/chat/completions
TENETSEC_AI_API_MODEL=gpt-4
```

You can find your tenant ID and client ID in the "Overview" section of your app registration.

## Configuring AI Recommendations

TenetSec can provide AI-powered security recommendations by using an external AI API. This functionality is optional but provides valuable context-aware security guidance.

### AI API Requirements

To use the AI recommendation feature, you'll need:
- An API key for a compatible Large Language Model API (OpenAI is used by default)
- Internet connectivity to reach the API endpoint

### API Privacy and Security

The AI recommendation engine anonymizes all tenant-specific data before sending it to the external API:
- Email addresses, domain names, UUIDs, and tenant identifiers are replaced with hash values
- User information is obfuscated to protect privacy
- No sensitive data is stored in the external AI service

### Configuration Options

#### Using Environment Variables

```bash
export TENETSEC_AI_API_KEY="your-api-key"
export TENETSEC_AI_API_ENDPOINT="https://api.openai.com/v1/chat/completions"
export TENETSEC_AI_API_MODEL="gpt-4"
```

#### Using config.json

Add an `ai_recommendations` section to your config.json:

```json
"ai_recommendations": {
  "enabled": true,
  "api_key": "your-api-key",
  "api_endpoint": "https://api.openai.com/v1/chat/completions",
  "api_model": "gpt-4"
}
```

If you don't configure an API key, TenetSec will still work but will use mock AI recommendations instead of generating customized ones.

## Running TenetSec

Once you've configured your authentication, you can run TenetSec:

```bash
python -m tenetsec.main
```

Or if you installed it with the entry point:

```bash
tenetsec
```

### Command Line Options

TenetSec supports several command line options:

```
usage: tenetsec.main [-h] [--config CONFIG] [--output-dir OUTPUT_DIR]
                     [--format {console,json,html,all}]
                     [--assessment {identity,defender,exchange,sharepoint,teams,all} [{identity,defender,exchange,sharepoint,teams,all} ...]]
                     [--debug]

TenetSec - Microsoft 365 Security Assessment Tool

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to configuration file
  --output-dir OUTPUT_DIR
                        Directory to save reports
  --format {console,json,html,all}
                        Report format (console, json, html, all)
  --assessment {identity,defender,exchange,sharepoint,teams,all} [{identity,defender,exchange,sharepoint,teams,all} ...]
                        Run specific assessment(s)
  --debug               Enable debug logging
```

For example, to run only the identity assessment and generate an HTML report:

```bash
tenetsec --assessment identity --format html
```

## Troubleshooting

If you encounter any issues:

1. **Authentication errors**: Verify your tenant ID, client ID, and client secret are correct
2. **Permission errors**: Ensure your app has the required permissions and admin consent
3. **Graph API errors**: Check the API endpoints and request format
4. **Debug mode**: Run with the `--debug` flag for more detailed logs

```bash
tenetsec --debug
```

## Next Steps

After setting up TenetSec, check out the [Usage Guide](usage.md) for detailed instructions on how to interpret the security assessment results and take action on findings.