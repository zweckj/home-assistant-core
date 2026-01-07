"""WebAuthn authentication provider for Home Assistant."""

from __future__ import annotations

from asyncio import Lock
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, Final

import voluptuous as vol
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from ..auth_store import AuthStore
from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.webauthn"

RP_NAME: Final = "Home Assistant"
RP_ID: Final = "home-assistant.io"

SIGN_IN_TIMEOUT_MS: Final = 60000
REGISTER_TIMEOUT_MS: Final = 60000

CONF_EXPECTED_ORIGIN: Final = "expected_origin"
CONF_AUTHENTICATION_CREDENTIAL: Final = "authentication_credential"


CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_EXPECTED_ORIGIN): vol.All(cv.ensure_list, [cv.url]),
    }
)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


type DataType = dict[str, dict[bytes, VerifiedRegistration]]


class PendingOperation[T]:
    """Class to hold pending operation with timestamp."""

    def __init__(self, options: T, created_at: datetime) -> None:
        """Initialize pending operation."""
        self.options = options
        self.created_at = created_at

    def is_expired(self, timeout: timedelta) -> bool:
        """Check if the operation has expired."""
        return dt_util.utcnow() > self.created_at + timeout


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

    async def async_add(
        self, username: str, registration: VerifiedRegistration
    ) -> None:
        """Store data to persistent storage."""
        user_creds = self._data.setdefault(username, {})
        user_creds[registration.credential_id] = registration
        await self._store.async_save(self._data)

    async def async_update_user_registration(
        self, username: str, verified_authentication: VerifiedAuthentication
    ) -> None:
        """Update credential data in after a successful authentication."""
        registration = self._data.get(username, {}).get(
            verified_authentication.credential_id
        )
        if registration:
            registration.sign_count = verified_authentication.new_sign_count
            registration.credential_device_type = (
                verified_authentication.credential_device_type
            )
            registration.credential_backed_up = (
                verified_authentication.credential_backed_up
            )
            await self._store.async_save(self._data)

    async def async_get_user_registered_credentials(
        self, username: str
    ) -> list[PublicKeyCredentialDescriptor]:
        """Retrieve allowed credentials for a user."""
        user_creds = self._data.get(username, {})
        return [PublicKeyCredentialDescriptor(id=cred_id) for cred_id in user_creds]

    async def async_get_user_registration(
        self, username: str, credential_id: bytes
    ) -> VerifiedRegistration | None:
        """Retrieve data from persistent storage."""
        return self._data.get(username, {}).get(credential_id)


@AUTH_PROVIDERS.register("webauthn")
class WebAuthnProvider(AuthProvider):
    """WebAuthn authentication provider for Home Assistant."""

    DEFAULT_TITLE = "WebAuthn Provider"

    def __init__(
        self, hass: HomeAssistant, store: AuthStore, config: dict[str, Any]
    ) -> None:
        """Initialize an auth provider."""
        super().__init__(hass, store, config)
        self.data: WebAuthnDataStore | None = None
        self._pending_registrations: dict[
            str, PendingOperation[PublicKeyCredentialCreationOptions]
        ] = {}
        self._pending_signins: dict[
            str, PendingOperation[PublicKeyCredentialRequestOptions]
        ] = {}
        self._init_lock = Lock()

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
            rp_name=RP_NAME,
            rp_id=RP_ID,
            user_name=username,
            timeout=REGISTER_TIMEOUT_MS,
        )
        self._pending_registrations[username] = PendingOperation(
            options, dt_util.utcnow()
        )
        return options

    async def async_complete_registration(
        self, username: str, credential: RegistrationCredential
    ) -> None:
        """Complete the registration of a new WebAuthn credential."""
        pending = self._pending_registrations.pop(username, None)
        if pending is None:
            raise InvalidAuthError("No pending registration found for user.")

        # Check if the registration has expired
        if pending.is_expired(timedelta(milliseconds=REGISTER_TIMEOUT_MS)):
            raise InvalidAuthError("Registration has expired.")

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=pending.options.challenge,
            expected_rp_id=RP_ID,
            expected_origin=self.config[CONF_EXPECTED_ORIGIN],
            require_user_verification=True,
        )

        # Store the credential information
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        await self.data.async_add(username, verification)

    async def async_start_authentication(
        self, username: str
    ) -> PublicKeyCredentialRequestOptions:
        """Start the authentication process."""

        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=await self.data.async_get_user_registered_credentials(
                username
            ),
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=SIGN_IN_TIMEOUT_MS,
        )
        self._pending_signins[username] = PendingOperation(options, dt_util.utcnow())
        return options

    async def async_complete_authentication(
        self, username: str, credential: AuthenticationCredential
    ) -> None:
        """Complete the authentication process."""
        pending = self._pending_signins.pop(username, None)
        if pending is None:
            raise InvalidAuthError("No pending authentication found for user.")

        # Check if the authentication has expired
        if pending.is_expired(timedelta(milliseconds=SIGN_IN_TIMEOUT_MS)):
            raise InvalidAuthError("Authentication has expired.")

        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        registration = await self.data.async_get_user_registration(
            username, credential.raw_id
        )
        if registration is None:
            raise InvalidAuthError("No registered credentials found for user.")

        try:
            response = verify_authentication_response(
                credential=credential,
                expected_challenge=pending.options.challenge,
                expected_rp_id=RP_ID,
                expected_origin=self.config[CONF_EXPECTED_ORIGIN],
                credential_public_key=registration.credential_public_key,
                credential_current_sign_count=registration.sign_count,
                require_user_verification=True,
            )
        except Exception as err:
            raise InvalidAuthError("Authentication failed.") from err

        # Update the sign count and other info
        await self.data.async_update_user_registration(username, response)

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
                await self._auth_provider.async_complete_authentication(
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
