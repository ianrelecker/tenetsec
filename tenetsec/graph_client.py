"""Microsoft Graph API client for TenetSec."""

import requests
from typing import Dict, Any, List, Optional
import logging
from .auth import GraphAuth

logger = logging.getLogger(__name__)


class GraphClient:
    """Client for interacting with Microsoft Graph API."""

    def __init__(self, auth: GraphAuth):
        """Initialize the Graph API client.

        Args:
            auth: Authenticated GraphAuth instance
        """
        self.auth = auth
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.headers = {}
        self._refresh_headers()

    def _refresh_headers(self) -> None:
        """Refresh the authorization headers with a new token."""
        token_data = self.auth.get_token()
        self.headers = {
            "Authorization": f"Bearer {token_data['access_token']}",
            "Content-Type": "application/json",
        }

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle the API response and check for errors.

        Args:
            response: Response from requests library

        Returns:
            Dict containing the response data or error information
        """
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            try:
                error_data = response.json()
                logger.error(f"Error details: {error_data}")
                return {"error": True, "status_code": response.status_code, "details": error_data}
            except ValueError:
                return {
                    "error": True,
                    "status_code": response.status_code,
                    "details": response.text,
                }
        except ValueError:
            logger.error("Response is not JSON format")
            return {"error": True, "details": "Invalid JSON response", "text": response.text}

    def _get_all_pages(self, url: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get all pages of results for paginated Graph API endpoints.

        Args:
            url: API endpoint URL
            params: Query parameters

        Returns:
            List of all items across all pages
        """
        all_items = []
        next_link = url
        
        while next_link:
            # Use original URL for first request, then use nextLink for subsequent requests
            if next_link != url:
                # nextLink already includes query parameters, so don't add them again
                response = requests.get(next_link, headers=self.headers)
            else:
                response = requests.get(url, headers=self.headers, params=params)
            
            data = self._handle_response(response)
            
            if "error" in data:
                logger.error(f"Error getting data from {url}: {data}")
                return all_items
            
            # Add the current page's results
            if "value" in data:
                all_items.extend(data["value"])
            
            # Check if there are more pages
            next_link = data.get("@odata.nextLink", None)
        
        return all_items

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a GET request to the Graph API.

        Args:
            endpoint: API endpoint (without base URL)
            params: Query parameters

        Returns:
            Response data as dict
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.get(url, headers=self.headers, params=params)
        return self._handle_response(response)

    def get_all(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get all pages of results from a paginated endpoint.

        Args:
            endpoint: API endpoint (without base URL)
            params: Query parameters

        Returns:
            List of all items
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self._get_all_pages(url, params)