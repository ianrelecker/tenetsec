"""Authentication module for Microsoft Graph API."""

import os
import msal
import json
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class GraphAuth:
    """Handles authentication with Microsoft Graph API."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[list] = None,
        config_file: Optional[str] = None,
    ):
        """Initialize the Graph API authentication handler.

        Args:
            tenant_id: The tenant ID for the M365 tenant
            client_id: The client ID for the Azure AD application
            client_secret: The client secret for the Azure AD application
            scopes: The Microsoft Graph API scopes to request
            config_file: Path to a JSON configuration file
        """
        # Default scopes needed for comprehensive security assessment
        self.default_scopes = [
            "https://graph.microsoft.com/.default",
        ]

        # Try to load config from file if provided
        if config_file and os.path.exists(config_file):
            with open(config_file, "r") as f:
                config = json.load(f)
                self.tenant_id = config.get("tenant_id", tenant_id)
                self.client_id = config.get("client_id", client_id)
                self.client_secret = config.get("client_secret", client_secret)
                self.scopes = config.get("scopes", scopes or self.default_scopes)
        else:
            # Use provided parameters or environment variables
            self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
            self.client_id = client_id or os.getenv("AZURE_CLIENT_ID")
            self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")
            self.scopes = scopes or self.default_scopes

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise ValueError(
                "Missing required authentication parameters. "
                "Provide tenant_id, client_id, and client_secret either directly, "
                "through a config file, or as environment variables."
            )

        # Initialize MSAL confidential client
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        self.token_cache = {}

    def get_token(self) -> Dict[str, Any]:
        """Acquire a token for Microsoft Graph API.

        Returns:
            Dict containing the access token and related information
        """
        # Check if we have a cached token that's still valid
        result = self.app.acquire_token_silent(self.scopes, account=None)

        # If no suitable token exists in cache, get a new one
        if not result:
            logger.info("No suitable token found in cache, acquiring new token")
            result = self.app.acquire_token_for_client(scopes=self.scopes)

            if "error" in result:
                error_msg = f"Error acquiring token: {result.get('error')}: {result.get('error_description')}"
                logger.error(error_msg)
                raise Exception(error_msg)

        return result