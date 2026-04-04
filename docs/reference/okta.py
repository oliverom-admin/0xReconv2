"""
Okta OAuth Provider

Implements OAuth 2.0 / OpenID Connect authentication using Okta's standard OIDC flow.

Configuration requirements:
- client_id: OAuth Client ID from Okta Admin Console
- client_secret: Client Secret from Okta Admin Console
- okta_domain: Your Okta domain (e.g., 'your-org.okta.com')
- redirect_uri: Redirect URI registered in Okta app settings

Free developer accounts: https://developer.okta.com/
"""

import logging
import requests
import hashlib
import base64
import secrets
from typing import Optional, Dict
from urllib.parse import urlencode

from caip_service_layer.oauth_service import (
    BaseOAuthProvider,
    OAuthConfig,
    OAuthToken,
    OAuthUserInfo
)

logger = logging.getLogger('caip.oauth.okta')


class OktaProvider(BaseOAuthProvider):
    """Okta OAuth provider using standard OIDC endpoints."""

    def __init__(self, config: OAuthConfig):
        super().__init__(config)

        # Get Okta domain from metadata or tenant_id
        self.okta_domain = config.metadata.get('okta_domain') or config.tenant_id
        if not self.okta_domain:
            raise ValueError("Okta domain (okta_domain or tenant_id) is required")

        # Normalize domain
        for prefix in ['https://', 'http://']:
            if self.okta_domain.startswith(prefix):
                self.okta_domain = self.okta_domain[len(prefix):]
        self.okta_domain = self.okta_domain.rstrip('/')

        # Auth server ID (default or custom)
        self.auth_server_id = config.metadata.get('authorization_server_id', 'default')

        # Build endpoints
        self.issuer = f'https://{self.okta_domain}/oauth2/{self.auth_server_id}'
        self.authorization_endpoint = f'{self.issuer}/v1/authorize'
        self.token_endpoint = f'{self.issuer}/v1/token'
        self.userinfo_endpoint = f'{self.issuer}/v1/userinfo'
        self.logout_endpoint = f'{self.issuer}/v1/logout'

        # PKCE support
        self.use_pkce = config.metadata.get('use_pkce', True)
        self._pkce_verifiers: Dict[str, str] = {}

        logger.info(f"Initialized Okta provider: domain={self.okta_domain}")

    def _generate_pkce_pair(self) -> tuple:
        """Generate PKCE code verifier and challenge."""
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        return code_verifier, code_challenge

    def get_authorization_url(self, state: str, nonce: Optional[str] = None) -> str:
        scopes = self.config.scopes or ['openid', 'profile', 'email']

        params = {
            'client_id': self.config.client_id,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'redirect_uri': self.config.redirect_uri,
            'state': state,
        }

        if nonce:
            params['nonce'] = nonce

        if self.use_pkce:
            code_verifier, code_challenge = self._generate_pkce_pair()
            self._pkce_verifiers[state] = code_verifier
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'

        logger.info(f"Generated Okta authorization URL for state={state}")
        return f'{self.authorization_endpoint}?{urlencode(params)}'

    def exchange_code_for_token(self, code: str, state: str) -> OAuthToken:
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'code': code,
            'redirect_uri': self.config.redirect_uri,
        }

        if self.use_pkce and state in self._pkce_verifiers:
            token_data['code_verifier'] = self._pkce_verifiers.pop(state)

        response = requests.post(
            self.token_endpoint,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )

        if response.status_code != 200:
            error_data = response.json() if response.content else {}
            error_desc = error_data.get('error_description', error_data.get('error', 'Unknown error'))
            logger.error(f"Token exchange failed: {error_desc}")
            raise ValueError(f"Token exchange failed: {error_desc}")

        result = response.json()
        logger.info("Successfully exchanged authorization code for access token")

        return OAuthToken(
            access_token=result['access_token'],
            token_type=result.get('token_type', 'Bearer'),
            expires_in=result.get('expires_in', 3600),
            refresh_token=result.get('refresh_token'),
            id_token=result.get('id_token'),
            scope=result.get('scope', '')
        )

    def get_user_info(self, token: OAuthToken) -> OAuthUserInfo:
        response = requests.get(
            self.userinfo_endpoint,
            headers={'Authorization': f'Bearer {token.access_token}'},
            timeout=10
        )

        if response.status_code != 200:
            logger.error(f"Userinfo error: {response.status_code}")
            raise ValueError(f"Failed to get user info: {response.status_code}")

        user_data = response.json()
        logger.info(f"Retrieved user info: email={user_data.get('email')}")

        return OAuthUserInfo(
            provider_user_id=user_data.get('sub'),
            email=user_data.get('email'),
            name=user_data.get('name'),
            given_name=user_data.get('given_name'),
            family_name=user_data.get('family_name'),
            username=user_data.get('preferred_username') or user_data.get('email'),
            roles=user_data.get('groups', []),
            raw_claims=user_data
        )

    def validate_token(self, token: OAuthToken) -> bool:
        try:
            self.get_user_info(token)
            return True
        except Exception as e:
            logger.warning(f"Token validation failed: {e}")
            return False

    def refresh_token(self, refresh_token: str) -> OAuthToken:
        refresh_data = {
            'grant_type': 'refresh_token',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'refresh_token': refresh_token,
        }

        if self.config.scopes:
            refresh_data['scope'] = ' '.join(self.config.scopes)

        response = requests.post(
            self.token_endpoint,
            data=refresh_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )

        if response.status_code != 200:
            error_data = response.json() if response.content else {}
            error_desc = error_data.get('error_description', 'Unknown error')
            logger.error(f"Token refresh failed: {error_desc}")
            raise ValueError(f"Token refresh failed: {error_desc}")

        result = response.json()
        logger.info("Successfully refreshed access token")

        return OAuthToken(
            access_token=result['access_token'],
            token_type=result.get('token_type', 'Bearer'),
            expires_in=result.get('expires_in', 3600),
            refresh_token=result.get('refresh_token', refresh_token),
            id_token=result.get('id_token'),
            scope=result.get('scope', '')
        )

    def get_logout_url(self, id_token_hint: Optional[str] = None,
                       post_logout_redirect_uri: Optional[str] = None) -> str:
        params = {}
        if id_token_hint:
            params['id_token_hint'] = id_token_hint
        if post_logout_redirect_uri:
            params['post_logout_redirect_uri'] = post_logout_redirect_uri

        if params:
            return f'{self.logout_endpoint}?{urlencode(params)}'
        return self.logout_endpoint
