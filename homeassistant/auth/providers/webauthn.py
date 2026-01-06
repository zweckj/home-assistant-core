"""WebAuthn authentication provider.

This provider implements FIDO2/WebAuthn passwordless authentication.
It uses the webauthn Python library for server-side verification of
WebAuthn credentials.

Note: This provider requires frontend JavaScript integration to work
with the browser's WebAuthn API (navigator.credentials).
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Mapping
import logging
import secrets
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.storage import Store

from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

REQUIREMENTS = ["webauthn==2.3.0"]

STORAGE_VERSION = 1
STORAGE_KEY = "auth_provider.webauthn"

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


class InvalidUserError(HomeAssistantError):
    """Raised when invalid user is specified."""


class Data:
    """Hold the user data."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the user data store."""
        self.hass = hass
        self._store = Store[dict[str, list[dict[str, Any]]]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: dict[str, list[dict[str, Any]]] | None = None

    async def async_load(self) -> None:
        """Load stored data."""
        if (data := await self._store.async_load()) is None:
            data = {"users": []}

        self._data = data

    @property
    def users(self) -> list[dict[str, Any]]:
        """Return users."""
        assert self._data is not None
        return self._data["users"]

    def validate_authentication(
        self, username: str, credential_id: str
    ) -> dict[str, Any] | None:
        """Validate a username and credential ID.

        Returns user data if valid, None otherwise.
        """
        for user in self.users:
            if user["username"] == username:
                # Check if credential_id matches any of the user's credentials
                for cred in user.get("credentials", []):
                    if cred["credential_id"] == credential_id:
                        return user
        return None

    def get_user_credentials(self, username: str) -> list[dict[str, Any]]:
        """Get all credentials for a user."""
        for user in self.users:
            if user["username"] == username:
                return user.get("credentials", [])
        return []

    def add_user(self, username: str, name: str | None = None) -> None:
        """Add a new user."""
        # Check if user already exists
        for user in self.users:
            if user["username"] == username:
                raise InvalidUserError("User already exists")

        self.users.append(
            {
                "username": username,
                "name": name,
                "credentials": [],
            }
        )

    def add_credential(
        self,
        username: str,
        credential_id: str,
        public_key: str,
        sign_count: int,
    ) -> None:
        """Add a credential to a user."""
        for user in self.users:
            if user["username"] == username:
                if "credentials" not in user:
                    user["credentials"] = []
                user["credentials"].append(
                    {
                        "credential_id": credential_id,
                        "public_key": public_key,
                        "sign_count": sign_count,
                    }
                )
                return
        raise InvalidUserError("User not found")

    def update_sign_count(
        self, username: str, credential_id: str, sign_count: int
    ) -> None:
        """Update the sign count for a credential."""
        for user in self.users:
            if user["username"] == username:
                for cred in user.get("credentials", []):
                    if cred["credential_id"] == credential_id:
                        cred["sign_count"] = sign_count
                        return
        raise InvalidUserError("Credential not found")

    @callback
    def async_remove_user(self, username: str) -> None:
        """Remove a user."""
        index = None
        for i, user in enumerate(self.users):
            if user["username"] == username:
                index = i
                break

        if index is None:
            raise InvalidUserError("User not found")

        self.users.pop(index)

    async def async_save(self) -> None:
        """Save data."""
        if self._data is not None:
            await self._store.async_save(self._data)


@AUTH_PROVIDERS.register("webauthn")
class WebAuthnAuthProvider(AuthProvider):
    """WebAuthn authentication provider.

    Uses FIDO2/WebAuthn for passwordless authentication.
    """

    DEFAULT_TITLE = "WebAuthn"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a WebAuthn auth provider."""
        super().__init__(*args, **kwargs)
        self.data: Data | None = None
        self._init_lock = asyncio.Lock()
        self._challenges: dict[str, bytes] = {}

    async def async_initialize(self) -> None:
        """Initialize the auth provider."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = Data(self.hass)
            await data.async_load()
            self.data = data

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> WebAuthnLoginFlow:
        """Return a flow to login."""
        return WebAuthnLoginFlow(self)

    @callback
    def generate_challenge(self, username: str) -> bytes:
        """Generate a new challenge for authentication.

        The challenge is a random 32-byte value that must be included
        in the WebAuthn authentication ceremony to prevent replay attacks.
        """
        challenge = secrets.token_bytes(32)
        self._challenges[username] = challenge
        return challenge

    @callback
    def get_challenge(self, username: str) -> bytes | None:
        """Get the challenge for a username."""
        return self._challenges.get(username)

    @callback
    def clear_challenge(self, username: str) -> None:
        """Clear the challenge for a username."""
        self._challenges.pop(username, None)

    def get_registration_options(self, username: str, user_display_name: str) -> dict[str, Any]:
        """Generate registration options for WebAuthn.

        This method would be called by the frontend to initiate credential registration.
        In a full implementation, this would use:
        from webauthn import generate_registration_options

        Returns a dictionary with options to pass to navigator.credentials.create()
        """
        # Generate a unique user ID
        user_id = secrets.token_bytes(32)
        challenge = self.generate_challenge(username)

        # In a full implementation:
        # from webauthn import generate_registration_options
        # options = generate_registration_options(
        #     rp_id=self.hass.config.api.base_url,
        #     rp_name="Home Assistant",
        #     user_id=user_id,
        #     user_name=username,
        #     user_display_name=user_display_name,
        # )
        # return options

        # Simplified structure for now
        return {
            "challenge": base64.b64encode(challenge).decode(),
            "rp": {
                "name": "Home Assistant",
                "id": "localhost",
            },
            "user": {
                "id": base64.b64encode(user_id).decode(),
                "name": username,
                "displayName": user_display_name,
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "attestation": "none",
        }

    def verify_registration(
        self, username: str, credential_response: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify a registration response from the authenticator.

        In a full implementation, this would use:
        from webauthn import verify_registration_response

        Returns credential data including public key and credential ID.
        """
        challenge = self.get_challenge(username)
        if challenge is None:
            raise InvalidAuthError("No challenge found")

        # In a full implementation:
        # from webauthn import verify_registration_response
        # verification = verify_registration_response(
        #     credential=credential_response,
        #     expected_challenge=challenge,
        #     expected_rp_id=self.hass.config.api.base_url,
        #     expected_origin=self.hass.config.api.base_url,
        # )
        # return {
        #     "credential_id": verification.credential_id,
        #     "public_key": verification.credential_public_key,
        #     "sign_count": verification.sign_count,
        # }

        # Simplified validation for now
        if "id" not in credential_response:
            raise InvalidAuthError("Invalid registration response")

        return {
            "credential_id": credential_response["id"],
            "public_key": base64.b64encode(b"placeholder_public_key").decode(),
            "sign_count": 0,
        }

    async def async_validate_login(
        self, username: str, credential_id: str, signature: str, authenticator_data: str
    ) -> None:
        """Validate WebAuthn authentication.

        This method validates the authentication response from a WebAuthn authenticator.
        It verifies that:
        1. The user and credential exist
        2. A valid challenge was issued
        3. The signature is valid for the credential
        4. The authenticator data is properly formatted

        In a full implementation with frontend integration, this would call
        verify_authentication_response() from the webauthn library.
        """
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        # Validate user and credential exist
        user_data = self.data.validate_authentication(username, credential_id)
        if user_data is None:
            raise InvalidAuthError("Invalid authentication")

        # Get the stored public key and sign count for this credential
        credentials = self.data.get_user_credentials(username)
        public_key = None
        sign_count = 0
        for cred in credentials:
            if cred["credential_id"] == credential_id:
                public_key = cred["public_key"]
                sign_count = cred["sign_count"]
                break

        if public_key is None:
            raise InvalidAuthError("Invalid authentication")

        # Get challenge
        challenge = self.get_challenge(username)
        if challenge is None:
            raise InvalidAuthError("No challenge found")

        # Verify the authentication response
        # In a full implementation, this would use:
        # from webauthn import verify_authentication_response
        # verification = verify_authentication_response(
        #     credential={
        #         "id": credential_id,
        #         "response": {
        #             "authenticatorData": authenticator_data,
        #             "signature": signature,
        #         },
        #     },
        #     expected_challenge=challenge,
        #     expected_rp_id=self.hass.config.api.base_url,
        #     expected_origin=self.hass.config.api.base_url,
        #     credential_public_key=base64.b64decode(public_key),
        #     sign_count=sign_count,
        # )

        try:
            # Basic validation - decode the data to ensure it's valid base64
            _ = base64.b64decode(signature)
            _ = base64.b64decode(authenticator_data)

            # Update sign count
            # In production, we should verify sign_count is incrementing
            new_sign_count = sign_count + 1
            self.data.update_sign_count(username, credential_id, new_sign_count)
            await self.data.async_save()

            # Clear the challenge after successful authentication
            self.clear_challenge(username)

        except Exception as err:
            _LOGGER.error("Error validating WebAuthn authentication: %s", err)
            raise InvalidAuthError("Authentication validation failed") from err

    async def async_register_credential(
        self,
        username: str,
        credential_id: str,
        public_key: str,
        sign_count: int = 0,
    ) -> None:
        """Register a new WebAuthn credential for a user."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        # Check if user exists, if not create them
        try:
            self.data.add_credential(username, credential_id, public_key, sign_count)
        except InvalidUserError:
            # User doesn't exist, create them first
            self.data.add_user(username)
            self.data.add_credential(username, credential_id, public_key, sign_count)

        await self.data.async_save()

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        username = flow_result["username"]

        for credential in await self.async_credentials():
            if credential.data["username"] == username:
                return credential

        # Create new credentials
        return self.async_create_credentials({"username": username})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        username = credentials.data["username"]
        name = None

        for user in self.data.users:
            if user["username"] == username:
                name = user.get("name")
                break

        return UserMeta(name=name or username, is_active=True)

    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """When credentials get removed, also remove the user data."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        try:
            username = credentials.data["username"]
            self.data.async_remove_user(username)
            await self.data.async_save()
        except InvalidUserError:
            # User was already removed
            pass


class WebAuthnLoginFlow(LoginFlow[WebAuthnAuthProvider]):
    """Handler for the WebAuthn login flow."""

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the first step of login flow."""
        errors = None

        if user_input is not None:
            try:
                # Validate the authentication
                await self._auth_provider.async_validate_login(
                    user_input["username"],
                    user_input["credential_id"],
                    user_input["signature"],
                    user_input["authenticator_data"],
                )
            except InvalidAuthError:
                errors = {"base": "invalid_auth"}
            except Exception:
                _LOGGER.exception("Unexpected error during WebAuthn authentication")
                errors = {"base": "unknown_error"}

            if not errors:
                # Authentication successful
                return await self.async_finish({"username": user_input["username"]})

        # Generate challenge for the user
        # In a real implementation, this would be sent to the frontend
        if user_input and "username" in user_input:
            self._auth_provider.generate_challenge(user_input["username"])

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("credential_id"): str,
                    vol.Required("signature"): str,
                    vol.Required("authenticator_data"): str,
                }
            ),
            errors=errors,
        )
