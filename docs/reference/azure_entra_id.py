"""
Azure Entra ID (Microsoft Azure AD) OAuth Provider

Implements OAuth 2.0 / OpenID Connect authentication using Microsoft MSAL library.

Supports:
- Single-tenant and multi-tenant Azure AD apps
- Authorization code flow with PKCE
- Token validation and refresh
- User profile retrieval from Microsoft Graph API
"""

import logging
import msal
import requests
from typing import Optional
from urllib.parse import urlencode

from caip_service_layer.oauth_service import (
    BaseOAuthProvider,
    OAuthConfig,
    OAuthToken,
    OAuthUserInfo
)

logger = logging.getLogger('caip.oauth.azure_entra_id')


class AzureEntraIDProvider(BaseOAuthProvider):
    """
    Azure Entra ID OAuth provider using MSAL.

    Configuration requirements:
    - client_id: Application (client) ID from Azure portal
    - client_secret: Client secret from Azure portal
    - tenant_id: Azure AD tenant ID (or 'common' for multi-tenant)
    - redirect_uri: Redirect URI registered in Azure portal
    """

    GRAPH_API_ENDPOINT = 'https://graph.microsoft.com/v1.0'

    def __init__(self, config: OAuthConfig):
        """
        Initialize Azure Entra ID provider.

        Args:
            config: OAuth provider configuration
        """
        super().__init__(config)

        # Build authority URL
        if config.authority_url:
            self.authority = config.authority_url
        elif config.tenant_id:
            self.authority = f'https://login.microsoftonline.com/{config.tenant_id}'
        else:
            # Default to common endpoint (multi-tenant)
            self.authority = 'https://login.microsoftonline.com/common'

        # Initialize MSAL confidential client app
        try:
            self.msal_app = msal.ConfidentialClientApplication(
                client_id=config.client_id,
                client_credential=config.client_secret,
                authority=self.authority
            )
            logger.info(f"Initialized Azure Entra ID provider: authority={self.authority}")
        except Exception as e:
            logger.error(f"Failed to initialize MSAL app: {e}")
            raise

    def get_authorization_url(self, state: str, nonce: Optional[str] = None) -> str:
        """
        Get the authorization URL for Azure AD OAuth flow.

        Args:
            state: CSRF protection state token
            nonce: Optional nonce for replay protection

        Returns:
            Authorization URL to redirect user to
        """
        try:
            # Filter out reserved scopes that MSAL automatically includes
            # Reserved scopes: 'openid', 'profile', 'offline_access'
            reserved_scopes = {'openid', 'profile', 'offline_access'}
            filtered_scopes = [s for s in self.config.scopes if s.lower() not in reserved_scopes]

            # If no scopes remain after filtering, use a minimal scope
            if not filtered_scopes:
                filtered_scopes = ['User.Read']

            logger.info(f"Requesting scopes (filtered): {filtered_scopes}")

            # Build auth URL using MSAL
            auth_params = {
                'scopes': filtered_scopes,
                'state': state,
                'redirect_uri': self.config.redirect_uri
            }

            if nonce:
                auth_params['nonce'] = nonce

            auth_url = self.msal_app.get_authorization_request_url(**auth_params)

            logger.info(f"Generated authorization URL for state={state}")
            return auth_url

        except Exception as e:
            logger.error(f"Error generating authorization URL: {e}")
            raise ValueError(f"Failed to generate authorization URL: {e}")

    def exchange_code_for_token(self, code: str, state: str) -> OAuthToken:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            state: State token for validation (not used here, validated by OAuthService)

        Returns:
            OAuthToken with access token and metadata

        Raises:
            ValueError: If code exchange fails
        """
        try:
            # Filter out reserved scopes (same as in get_authorization_url)
            reserved_scopes = {'openid', 'profile', 'offline_access'}
            filtered_scopes = [s for s in self.config.scopes if s.lower() not in reserved_scopes]

            if not filtered_scopes:
                filtered_scopes = ['User.Read']

            # Exchange code for token using MSAL
            result = self.msal_app.acquire_token_by_authorization_code(
                code=code,
                scopes=filtered_scopes,
                redirect_uri=self.config.redirect_uri
            )

            # Check for errors
            if 'error' in result:
                error_desc = result.get('error_description', result['error'])
                logger.error(f"Token exchange failed: {error_desc}")
                raise ValueError(f"Token exchange failed: {error_desc}")

            # Build OAuthToken
            token = OAuthToken(
                access_token=result['access_token'],
                token_type=result.get('token_type', 'Bearer'),
                expires_in=result.get('expires_in', 3600),
                refresh_token=result.get('refresh_token'),
                id_token=result.get('id_token'),
                scope=' '.join(filtered_scopes)
            )

            logger.info("Successfully exchanged authorization code for access token")
            return token

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error exchanging code for token: {e}")
            raise ValueError(f"Token exchange failed: {e}")

    def get_user_info(self, token: OAuthToken) -> OAuthUserInfo:
        """
        Get user information from Microsoft Graph API.

        Args:
            token: OAuth token with access token

        Returns:
            OAuthUserInfo with user details

        Raises:
            ValueError: If user info retrieval fails
        """
        try:
            # Call Microsoft Graph API /me endpoint
            headers = {
                'Authorization': f'Bearer {token.access_token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'{self.GRAPH_API_ENDPOINT}/me',
                headers=headers,
                timeout=10
            )

            if response.status_code != 200:
                logger.error(f"Graph API error: {response.status_code} - {response.text}")
                raise ValueError(f"Failed to get user info: {response.status_code}")

            user_data = response.json()

            # Parse user info
            user_info = OAuthUserInfo(
                provider_user_id=user_data.get('id'),  # Azure object ID (OID)
                email=user_data.get('mail') or user_data.get('userPrincipalName'),
                name=user_data.get('displayName'),
                given_name=user_data.get('givenName'),
                family_name=user_data.get('surname'),
                username=user_data.get('userPrincipalName'),
                raw_claims=user_data
            )

            logger.info(f"Retrieved user info: email={user_info.email}")
            return user_info

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            raise ValueError(f"Failed to get user info: {e}")

    def validate_token(self, token: OAuthToken) -> bool:
        """
        Validate an access token by attempting to use it.

        Args:
            token: OAuth token to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            # Try to get user info - if it works, token is valid
            self.get_user_info(token)
            return True
        except Exception as e:
            logger.warning(f"Token validation failed: {e}")
            return False

    def refresh_token(self, refresh_token: str) -> OAuthToken:
        """
        Refresh an expired access token.

        Args:
            refresh_token: Refresh token

        Returns:
            New OAuthToken

        Raises:
            ValueError: If refresh fails
        """
        try:
            # Filter out reserved scopes (same as in other methods)
            reserved_scopes = {'openid', 'profile', 'offline_access'}
            filtered_scopes = [s for s in self.config.scopes if s.lower() not in reserved_scopes]

            if not filtered_scopes:
                filtered_scopes = ['User.Read']

            # Refresh token using MSAL
            result = self.msal_app.acquire_token_by_refresh_token(
                refresh_token=refresh_token,
                scopes=filtered_scopes
            )

            # Check for errors
            if 'error' in result:
                error_desc = result.get('error_description', result['error'])
                logger.error(f"Token refresh failed: {error_desc}")
                raise ValueError(f"Token refresh failed: {error_desc}")

            # Build new OAuthToken
            token = OAuthToken(
                access_token=result['access_token'],
                token_type=result.get('token_type', 'Bearer'),
                expires_in=result.get('expires_in', 3600),
                refresh_token=result.get('refresh_token', refresh_token),
                id_token=result.get('id_token'),
                scope=' '.join(filtered_scopes)
            )

            logger.info("Successfully refreshed access token")
            return token

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            raise ValueError(f"Token refresh failed: {e}")

    def get_logout_url(self, post_logout_redirect_uri: Optional[str] = None) -> str:
        """
        Get the Azure AD logout URL.

        Args:
            post_logout_redirect_uri: URL to redirect to after logout

        Returns:
            Logout URL
        """
        logout_url = f'{self.authority}/oauth2/v2.0/logout'

        if post_logout_redirect_uri:
            params = {'post_logout_redirect_uri': post_logout_redirect_uri}
            logout_url = f'{logout_url}?{urlencode(params)}'

        return logout_url
