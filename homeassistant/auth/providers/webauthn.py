"""WebAuthn authentication provider for Home Assistant."""

from __future__ import annotations

from asyncio import Lock
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import time
from typing import Any, Final, cast

import voluptuous as vol
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticationCredential,
    CredentialDeviceType,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    UserVerificationRequirement,
)

from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.storage import Store

from ..auth_store import AuthStore
from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

WEBAUTHN_PROVIDER_TYPE: Final = "webauthn"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.webauthn"

SIGN_IN_TIMEOUT_MS: Final = 60000
REGISTER_TIMEOUT_MS: Final = 60000

CONF_RP_ID: Final = "rp_id"
CONF_RP_NAME: Final = "rp_name"
CONF_EXPECTED_ORIGIN: Final = "expected_origin"
CONF_AUTHENTICATION_CREDENTIAL: Final = "authentication_credential"


CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_RP_ID): str,
        vol.Required(CONF_RP_NAME, default="Home Assistant"): str,
        vol.Required(CONF_EXPECTED_ORIGIN): vol.All(cv.ensure_list, [cv.url]),
    }
)


@callback
def async_get_provider(hass: HomeAssistant) -> WebAuthnProvider:
    """Get the provider."""
    for prv in hass.auth.auth_providers:
        if prv.type == WEBAUTHN_PROVIDER_TYPE:
            return cast(WebAuthnProvider, prv)
    raise RuntimeError("Provider not found")


@dataclass
class WebAuthnCredential:
    """Class to hold WebAuthn registration data."""

    credential_id: str
    credential_public_key: str
    sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool
    name: str = "Passkey"
    created_at: float = field(default_factory=time)
    last_used_at: float = field(default_factory=time)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


class CredentialNotFoundError(HomeAssistantError):
    """Raised when submitting invalid credential."""


type DataType = dict[str, dict[str, WebAuthnCredential]]


class WebAuthnDataStore:
    """Class to hold WebAuthn related data."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize WebAuthn data."""
        self._store = Store[DataType](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: DataType = {}

    async def async_load(self) -> None:
        """Load data from persistent storage."""
        if (data := await self._store.async_load()) is None:
            data = {}

        self._data = data

    async def async_add_credential(
        self, username: str, credential: WebAuthnCredential
    ) -> None:
        """Store data to persistent storage."""

        user_creds = self._data.setdefault(username, {})
        user_creds[credential.credential_id] = credential
        await self._store.async_save(self._data)

    async def async_delete_credential(self, username: str, credential_id: str) -> None:
        """Delete credential from persistent storage."""
        if (self._data.get(username, {}).pop(credential_id, None)) is None:
            raise CredentialNotFoundError("Credential not found.")
        await self._store.async_save(self._data)

    async def async_rename_credential(
        self, username: str, credential_id: str, new_name: str
    ) -> None:
        """Rename credential in persistent storage."""
        if (credential := self._data.get(username, {}).get(credential_id)) is None:
            raise CredentialNotFoundError("Credential not found.")
        credential.name = new_name
        await self._store.async_save(self._data)

    async def async_update_user_registration(
        self,
        username: str,
        credential_id: str,
        new_sign_count: int,
        credential_device_type: CredentialDeviceType,
        credential_backed_up: bool,
    ) -> None:
        """Update credential data in after a successful authentication."""
        if registration := self._data.get(username, {}).get(credential_id):
            registration.sign_count = new_sign_count
            registration.credential_device_type = credential_device_type
            registration.credential_backed_up = credential_backed_up
            registration.last_used_at = time()
            await self._store.async_save(self._data)

    async def async_get_user_registered_credentials(
        self, username: str
    ) -> list[PublicKeyCredentialDescriptor]:
        """Retrieve allowed credentials for a user."""
        user_creds = self._data.get(username, {})
        return [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in user_creds
        ]

    async def async_list_credentials(self, username: str) -> list[WebAuthnCredential]:
        """Retrieve all registered credentials for a user."""
        if (user_creds := self._data.get(username)) is None:
            return []
        return list(user_creds.values())

    async def async_get_user_credential(
        self, username: str, credential_id: str
    ) -> WebAuthnCredential | None:
        """Retrieve data from persistent storage."""

        return self._data.get(username, {}).get(credential_id)


@AUTH_PROVIDERS.register(WEBAUTHN_PROVIDER_TYPE)
class WebAuthnProvider(AuthProvider):
    """WebAuthn authentication provider for Home Assistant."""

    DEFAULT_TITLE = "WebAuthn Provider"

    def __init__(
        self, hass: HomeAssistant, store: AuthStore, config: dict[str, Any]
    ) -> None:
        """Initialize an auth provider."""
        super().__init__(hass, store, config)
        self.data: WebAuthnDataStore | None = None

        # store the challenges for pending registrations and signins for each user
        self._pending_registration_challenges: dict[str, bytes] = {}
        self._pending_signin_challenges: dict[str, bytes] = {}

        self._init_lock = Lock()
        self._registration_lock = Lock()
        self._signin_lock = Lock()

    @property
    def support_mfa(self) -> bool:
        """Return whether multi-factor auth supported by the auth provider."""
        return False

    async def async_initialize(self) -> None:
        """Initialize the auth provider."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = WebAuthnDataStore(self.hass)
            await data.async_load()
            self.data = data

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> WebAuthnLoginFlow:
        """Return a flow to login."""
        return WebAuthnLoginFlow(self)

    async def async_start_registration(
        self, username: str
    ) -> PublicKeyCredentialCreationOptions:
        """Register a new WebAuthn credential."""

        # Do we have a list of pub key algorithms to support?
        options = generate_registration_options(
            rp_name=self.config[CONF_RP_NAME],
            rp_id=self.config[CONF_RP_ID],
            user_name=username,
            timeout=REGISTER_TIMEOUT_MS,
        )

        async with self._registration_lock:
            self._pending_registration_challenges[username] = options.challenge

        # clean the challenge after timeout
        self._async_safe_remove_pending_challenges(
            username=username,
            challenge_dict=self._pending_registration_challenges,
            challenge=options.challenge,
            timeout=REGISTER_TIMEOUT_MS,
            lock=self._registration_lock,
        )
        return options

    async def async_verify_registration(
        self, username: str, credential: RegistrationCredential
    ) -> None:
        """Complete the registration of a new WebAuthn credential."""
        async with self._registration_lock:
            challenge = self._pending_registration_challenges.pop(username, None)

        if challenge is None:
            raise InvalidAuthError("No pending registration found for user.")

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self.config[CONF_RP_ID],
            expected_origin=self.config[CONF_EXPECTED_ORIGIN],
            require_user_verification=True,
        )

        # Store the credential information
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        web_authn_credential = WebAuthnCredential(
            credential_id=bytes_to_base64url(verification.credential_id),
            credential_public_key=bytes_to_base64url(
                verification.credential_public_key
            ),
            sign_count=verification.sign_count,
            credential_device_type=verification.credential_device_type,
            credential_backed_up=verification.credential_backed_up,
        )

        await self.data.async_add_credential(username, web_authn_credential)

    async def async_start_authentication(
        self, username: str
    ) -> PublicKeyCredentialRequestOptions:
        """Start the authentication process."""

        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        options = generate_authentication_options(
            rp_id=self.config[CONF_RP_ID],
            allow_credentials=await self.data.async_get_user_registered_credentials(
                username
            ),
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=SIGN_IN_TIMEOUT_MS,
        )
        async with self._signin_lock:
            self._pending_signin_challenges[username] = options.challenge

        # clean the challenge after timeout
        self._async_safe_remove_pending_challenges(
            username=username,
            challenge=options.challenge,
            challenge_dict=self._pending_signin_challenges,
            timeout=SIGN_IN_TIMEOUT_MS,
            lock=self._signin_lock,
        )
        return options

    async def async_verify_authentication(
        self, username: str, credential: AuthenticationCredential
    ) -> None:
        """Complete the authentication process."""

        async with self._signin_lock:
            challenge = self._pending_signin_challenges.pop(username, None)

        if challenge is None:
            raise InvalidAuthError("No pending authentication found for user.")

        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        registration = await self.data.async_get_user_credential(
            username, credential.id
        )
        if registration is None:
            raise InvalidAuthError("No registered credentials found for user.")

        try:
            response = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.config[CONF_RP_ID],
                expected_origin=self.config[CONF_EXPECTED_ORIGIN],
                credential_public_key=base64url_to_bytes(
                    registration.credential_public_key
                ),
                credential_current_sign_count=registration.sign_count,
                require_user_verification=True,
            )
        except Exception as err:
            raise InvalidAuthError("Authentication failed.") from err

        # Update the sign count and other info
        await self.data.async_update_user_registration(
            username=username,
            credential_id=bytes_to_base64url(response.credential_id),
            new_sign_count=response.new_sign_count,
            credential_device_type=response.credential_device_type,
            credential_backed_up=response.credential_backed_up,
        )

    async def async_delete_credential(self, username: str, credential_id: str) -> None:
        """Delete a registered credential."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        await self.data.async_delete_credential(username, credential_id)

    async def async_list_credentials(self, username: str) -> list[WebAuthnCredential]:
        """List all registered credentials for a user."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        return await self.data.async_list_credentials(username=username)

    async def async_rename_credential(
        self,
        username: str,
        credential_id: str,
        new_name: str,
    ) -> None:
        """Rename a registered credential for a user."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        await self.data.async_rename_credential(username, credential_id, new_name)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""

        username = flow_result[CONF_USERNAME]

        for credential in await self.async_credentials():
            if credential.data[CONF_USERNAME] == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({CONF_USERNAME: username})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """

        return UserMeta(name=credentials.data[CONF_USERNAME], is_active=True)

    @callback
    def _async_safe_remove_pending_challenges(
        self,
        username: str,
        challenge_dict: dict[str, bytes],
        challenge: bytes,
        timeout: int,
        lock: Lock,
    ) -> None:
        """Remove a pending challenge for a user after a timeout."""

        async def remove_challenge(_: Any) -> None:
            async with lock:
                chall = challenge_dict.get(username)
                if chall is not None and chall == challenge:
                    challenge_dict.pop(username)

        async_call_later(
            self.hass,
            timeout / 1000,
            remove_challenge,
        )


class WebAuthnLoginFlow(LoginFlow[WebAuthnProvider]):
    """Handler for the login flow."""

    username: str

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Initialize the login flow."""

        errors: dict[str, str] = {}

        if user_input is not None:
            self.username = user_input[CONF_USERNAME]
            try:
                options = await self._auth_provider.async_start_authentication(
                    user_input[CONF_USERNAME]
                )
            except InvalidAuthError:
                errors["base"] = "invalid_auth"
            else:
                return self.async_show_form(
                    step_id="verify_credential",
                    description_placeholders={
                        "webauthn_options": options_to_json(options)
                    },
                )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                }
            ),
            errors=errors,
        )

    async def async_step_verify_credential(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Handle submission of authentication credential."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                await self._auth_provider.async_verify_authentication(
                    self.username, user_input[CONF_AUTHENTICATION_CREDENTIAL]
                )
            except InvalidAuthError:
                errors["base"] = "invalid_auth"
            else:
                return await self.async_finish(user_input)

        return self.async_show_form(
            step_id="challenge",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_AUTHENTICATION_CREDENTIAL
                    ): AuthenticationCredential,
                }
            ),
            errors=errors,
        )
