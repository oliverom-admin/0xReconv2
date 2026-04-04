"""
OAuth/MSAL Authentication Service Layer for CAIP

Provides a provider-agnostic OAuth 2.0 / OpenID Connect authentication framework
with support for multiple identity providers.

Supported Providers:
- Azure Entra ID (Microsoft Azure AD) via MSAL
- Extensible architecture for future providers (Okta, Auth0, Google, etc.)

Architecture:
- BaseOAuthProvider: Abstract base class defining OAuth flow interface
- Concrete providers: AzureEntraIDProvider, etc.
- OAuthService: Facade for managing providers and authentication flows
"""

import logging
import secrets
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger('caip.operational')


# ==================== DATA MODELS ====================

@dataclass
class OAuthConfig:
    """OAuth provider configuration"""
    provider_id: int
    provider_type: str  # 'azure_entra_id', 'okta', 'auth0', etc.
    provider_name: str
    client_id: str
    client_secret: str
    tenant_id: Optional[str] = None  # Azure-specific
    authority_url: Optional[str] = None
    redirect_uri: str = None
    scopes: list = None
    enabled: bool = True
    auto_provision_users: bool = False  # Auto-create users on first login
    default_role: str = 'report-user'  # Role for auto-provisioned users
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ['openid', 'profile', 'email']
        if self.metadata is None:
            self.metadata = {}


@dataclass
class OAuthToken:
    """OAuth token response"""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: Optional[str] = None

    @property
    def expires_at(self) -> datetime:
        """Calculate token expiration time"""
        return datetime.utcnow() + timedelta(seconds=self.expires_in)


@dataclass
class OAuthUserInfo:
    """User information from OAuth provider"""
    provider_user_id: str  # Unique ID from provider (e.g., Azure OID)
    email: str
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    username: Optional[str] = None
    roles: list = None
    raw_claims: Dict[str, Any] = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.raw_claims is None:
            self.raw_claims = {}


# ==================== BASE OAUTH PROVIDER ====================

class BaseOAuthProvider(ABC):
    """
    Abstract base class for OAuth 2.0 / OpenID Connect providers.

    Defines the interface all OAuth providers must implement.
    """

    def __init__(self, config: OAuthConfig):
        """
        Initialize OAuth provider.

        Args:
            config: OAuth provider configuration
        """
        self.config = config
        self.logger = logging.getLogger(f'caip.oauth.{config.provider_type}')

    @abstractmethod
    def get_authorization_url(self, state: str, nonce: Optional[str] = None) -> str:
        """
        Get the authorization URL for the OAuth flow.

        Args:
            state: CSRF protection state token
            nonce: Optional nonce for replay protection

        Returns:
            Authorization URL to redirect user to
        """
        pass

    @abstractmethod
    def exchange_code_for_token(self, code: str, state: str) -> OAuthToken:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            state: State token for validation

        Returns:
            OAuthToken with access token and metadata

        Raises:
            ValueError: If code exchange fails
        """
        pass

    @abstractmethod
    def get_user_info(self, token: OAuthToken) -> OAuthUserInfo:
        """
        Get user information using access token.

        Args:
            token: OAuth token with access token

        Returns:
            OAuthUserInfo with user details

        Raises:
            ValueError: If user info retrieval fails
        """
        pass

    @abstractmethod
    def validate_token(self, token: OAuthToken) -> bool:
        """
        Validate an access token.

        Args:
            token: OAuth token to validate

        Returns:
            True if valid, False otherwise
        """
        pass

    @abstractmethod
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
        pass


# ==================== OAUTH SERVICE ====================

class OAuthService:
    """
    Central service for managing OAuth authentication flows.

    Responsibilities:
    - Provider registration and lifecycle management
    - State token generation and validation
    - User provisioning and account linking
    - Session management integration
    """

    # In-memory state storage (in production, use Redis or database)
    _state_store: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def generate_state_token(cls, provider_id: int, redirect_after_login: str = '/dashboard') -> str:
        """
        Generate a CSRF-protection state token for OAuth flow.

        Args:
            provider_id: Database ID of the auth provider
            redirect_after_login: URL to redirect to after successful login

        Returns:
            State token (store this in session)
        """
        state = secrets.token_urlsafe(32)
        cls._state_store[state] = {
            'provider_id': provider_id,
            'redirect_uri': redirect_after_login,
            'created_at': datetime.utcnow(),
            'nonce': secrets.token_urlsafe(16)
        }

        # Clean up old state tokens (older than 10 minutes)
        cls._cleanup_expired_states()

        return state

    @classmethod
    def validate_state_token(cls, state: str) -> Optional[Dict[str, Any]]:
        """
        Validate and consume a state token.

        Args:
            state: State token from OAuth callback

        Returns:
            State data if valid, None otherwise
        """
        state_data = cls._state_store.pop(state, None)

        if not state_data:
            logger.warning(f"Invalid or expired state token: {state}")
            return None

        # Check if token is expired (10 minutes)
        age = (datetime.utcnow() - state_data['created_at']).total_seconds()
        if age > 600:  # 10 minutes
            logger.warning(f"State token expired (age: {age}s)")
            return None

        return state_data

    @classmethod
    def _cleanup_expired_states(cls):
        """Remove state tokens older than 10 minutes"""
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        expired = [
            state for state, data in cls._state_store.items()
            if data['created_at'] < cutoff
        ]
        for state in expired:
            del cls._state_store[state]

    @classmethod
    def get_provider(cls, provider_id: int) -> Optional[BaseOAuthProvider]:
        """
        Get an OAuth provider instance by ID.

        Args:
            provider_id: Database ID of the auth provider

        Returns:
            Provider instance or None if not found/disabled
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM auth_providers WHERE id = ?', (provider_id,))
            row = c.fetchone()
            conn.close()

            if not row:
                logger.warning(f"Auth provider {provider_id} not found")
                return None

            provider_data = DatabaseService.dict_from_row(row)

            if not provider_data.get('enabled', False):
                logger.warning(f"Auth provider {provider_id} is disabled")
                return None

            # Parse configuration
            config_json = json.loads(provider_data['config_json'])

            # Build OAuthConfig
            oauth_config = OAuthConfig(
                provider_id=provider_data['id'],
                provider_type=provider_data['type'],
                provider_name=provider_data['name'],
                client_id=config_json.get('client_id'),
                client_secret=config_json.get('client_secret'),
                tenant_id=config_json.get('tenant_id'),
                authority_url=config_json.get('authority_url'),
                redirect_uri=config_json.get('redirect_uri'),
                scopes=config_json.get('scopes', ['openid', 'profile', 'email']),
                enabled=provider_data.get('enabled', True),
                auto_provision_users=config_json.get('auto_provision_users', False),
                default_role=config_json.get('default_role', 'report-user'),
                metadata=config_json.get('metadata', {})
            )

            # Instantiate provider based on type
            if provider_data['type'] == 'azure_entra_id':
                from caip_service_layer.oauth_providers.azure_entra_id import AzureEntraIDProvider
                return AzureEntraIDProvider(oauth_config)
            elif provider_data['type'] == 'okta':
                from caip_service_layer.oauth_providers.okta import OktaProvider
                return OktaProvider(oauth_config)
            else:
                logger.error(f"Unknown provider type: {provider_data['type']}")
                return None

        except Exception as e:
            logger.error(f"Error loading OAuth provider {provider_id}: {e}")
            return None

    @classmethod
    def get_all_enabled_providers(cls) -> list:
        """
        Get all enabled OAuth providers.

        Returns:
            List of provider dictionaries
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM auth_providers WHERE enabled = 1 ORDER BY name')
            rows = c.fetchall()
            conn.close()

            providers = []
            for row in rows:
                provider = DatabaseService.dict_from_row(row)
                # Don't expose secrets in the list
                config = json.loads(provider['config_json'])
                provider['config_summary'] = {
                    'client_id': config.get('client_id', ''),
                    'tenant_id': config.get('tenant_id', ''),
                    'scopes': config.get('scopes', [])
                }
                del provider['config_json']
                providers.append(provider)

            return providers

        except Exception as e:
            logger.error(f"Error getting enabled OAuth providers: {e}")
            return []

    @classmethod
    def provision_or_link_user(cls, oauth_user: OAuthUserInfo, provider_id: int, auto_provision: bool) -> Optional[int]:
        """
        Provision a new user or link to existing user based on OAuth user info.

        Args:
            oauth_user: User information from OAuth provider
            provider_id: Database ID of the auth provider
            auto_provision: Whether to auto-create users

        Returns:
            User ID if successful, None otherwise
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            # Check if user already linked via oauth_user_links table
            c.execute('''SELECT user_id FROM oauth_user_links
                         WHERE provider_id = ? AND provider_user_id = ?''',
                     (provider_id, oauth_user.provider_user_id))
            link = c.fetchone()

            if link:
                # User already linked - ensure auth_provider_id is set in users table
                user_id = link['user_id']

                # Update user's auth_provider_id if not already set
                c.execute('UPDATE users SET auth_provider_id = ? WHERE id = ? AND auth_provider_id IS NULL',
                         (provider_id, user_id))
                conn.commit()

                logger.info(f"Existing OAuth user link found: user_id={user_id}")
                conn.close()
                return user_id

            # Check if user exists by email
            c.execute('SELECT id FROM users WHERE username = ?', (oauth_user.email,))
            existing_user = c.fetchone()

            if existing_user:
                # Link existing user to OAuth provider
                user_id = existing_user['id']

                # Update user's auth_provider_id if not already set
                c.execute('UPDATE users SET auth_provider_id = ? WHERE id = ? AND auth_provider_id IS NULL',
                         (provider_id, user_id))

                c.execute('''INSERT INTO oauth_user_links
                             (user_id, provider_id, provider_user_id, email, name)
                             VALUES (?, ?, ?, ?, ?)''',
                         (user_id, provider_id, oauth_user.provider_user_id,
                          oauth_user.email, oauth_user.name))
                conn.commit()
                logger.info(f"Linked existing user {oauth_user.email} to OAuth provider {provider_id}")
                conn.close()
                return user_id

            # User doesn't exist - check if auto-provisioning is enabled
            if not auto_provision:
                logger.warning(f"User {oauth_user.email} not found and auto-provisioning is disabled")
                conn.close()
                return None

            # Auto-provision new user
            from database_service import DatabaseService
            default_role = 'report-user'  # Safe default

            # Get default role from provider config
            c.execute('SELECT config_json FROM auth_providers WHERE id = ?', (provider_id,))
            provider = c.fetchone()
            if provider:
                config = json.loads(provider['config_json'])
                default_role = config.get('default_role', 'report-user')

            # Create user (no password needed for OAuth users)
            import secrets
            dummy_password = secrets.token_urlsafe(32)  # Never used, just for schema
            from werkzeug.security import generate_password_hash

            # Get role_id from roles table
            c.execute('SELECT id FROM roles WHERE name = ?', (default_role,))
            role_row = c.fetchone()
            role_id = role_row[0] if role_row else None

            c.execute('''INSERT INTO users (username, password, role, role_id, auth_provider_id)
                         VALUES (?, ?, ?, ?, ?)''',
                     (oauth_user.email, generate_password_hash(dummy_password), default_role, role_id, provider_id))
            user_id = c.lastrowid

            # Create OAuth link
            c.execute('''INSERT INTO oauth_user_links
                         (user_id, provider_id, provider_user_id, email, name)
                         VALUES (?, ?, ?, ?, ?)''',
                     (user_id, provider_id, oauth_user.provider_user_id,
                      oauth_user.email, oauth_user.name))

            conn.commit()
            conn.close()

            logger.info(f"Auto-provisioned new user: {oauth_user.email} (user_id={user_id}, role={default_role})")
            return user_id

        except Exception as e:
            logger.error(f"Error provisioning/linking OAuth user: {e}")
            import traceback
            traceback.print_exc()
            return None
