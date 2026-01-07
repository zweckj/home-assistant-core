"""WebAuthn authentication provider for Home Assistant."""

from __future__ import annotations

from asyncio import Lock
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import time
from typing import Any, Final

import voluptuous as vol
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
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
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.storage import Store

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


@dataclass
class WebAuthnRegistration:
    """Class to hold WebAuthn registration data."""

    credential_id: bytes
    credential_public_key: bytes
    sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool
    created_at: float = field(default_factory=time)
    last_used_at: float = field(default_factory=time)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


type DataType = dict[str, dict[bytes, WebAuthnRegistration]]


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
        self, username: str, registration: WebAuthnRegistration
    ) -> None:
        """Store data to persistent storage."""

        user_creds = self._data.setdefault(username, {})
        user_creds[registration.credential_id] = registration
        await self._store.async_save(self._data)

    async def async_update_user_registration(
        self,
        username: str,
        credential_id: bytes,
        new_sign_count: int,
        credential_device_type: CredentialDeviceType,
        credential_backed_up: bool,
    ) -> None:
        """Update credential data in after a successful authentication."""
        registration = self._data.get(username, {}).get(credential_id)
        if registration:
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
        return [PublicKeyCredentialDescriptor(id=cred_id) for cred_id in user_creds]

    async def async_get_user_registration(
        self, username: str, credential_id: bytes
    ) -> WebAuthnRegistration | None:
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
        # TODO expire pending registrations/signins after their respective timeouts
        self._pending_registrations: dict[str, PublicKeyCredentialCreationOptions] = {}
        self._pending_signins: dict[str, PublicKeyCredentialRequestOptions] = {}
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
        self._pending_registrations[username] = options
        return options

    async def async_complete_registration(
        self, username: str, credential: RegistrationCredential
    ) -> None:
        """Complete the registration of a new WebAuthn credential."""
        options = self._pending_registrations.pop(username, None)
        if options is None:
            raise InvalidAuthError("No pending registration found for user.")

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=options.challenge,
            expected_rp_id=RP_ID,
            expected_origin=self.config[CONF_EXPECTED_ORIGIN],
            require_user_verification=True,
        )

        # Store the credential information
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        registration = WebAuthnRegistration(
            credential_id=verification.credential_id,
            credential_public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            credential_device_type=verification.credential_device_type,
            credential_backed_up=verification.credential_backed_up,
        )

        await self.data.async_add(username, registration)

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
        self._pending_signins[username] = options
        return options

    async def async_complete_authentication(
        self, username: str, credential: AuthenticationCredential
    ) -> None:
        """Complete the authentication process."""
        options = self._pending_signins.pop(username, None)
        if options is None:
            raise InvalidAuthError("No pending authentication found for user.")

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
                expected_challenge=options.challenge,
                expected_rp_id=RP_ID,
                expected_origin=self.config[CONF_EXPECTED_ORIGIN],
                credential_public_key=registration.credential_public_key,
                credential_current_sign_count=registration.sign_count,
                require_user_verification=True,
            )
        except Exception as err:
            raise InvalidAuthError("Authentication failed.") from err

        # Update the sign count and other info
        await self.data.async_update_user_registration(
            username=username,
            credential_id=response.credential_id,
            new_sign_count=response.new_sign_count,
            credential_device_type=response.credential_device_type,
            credential_backed_up=response.credential_backed_up,
        )

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
