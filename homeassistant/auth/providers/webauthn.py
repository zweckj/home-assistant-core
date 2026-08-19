"""WebAuthn authentication provider for Home Assistant."""

from asyncio import Lock
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import time
from typing import Any, Final, NamedTuple, cast, override

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
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
import yarl

from homeassistant.const import CONF_ID
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.network import is_hass_url
from homeassistant.helpers.storage import Store
from homeassistant.util.network import is_ip_address

from ..auth_store import AuthStore
from ..models import AuthFlowContext, AuthFlowResult, Credentials, User, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

REQUIREMENTS = ["webauthn==3.0.0"]

WEBAUTHN_PROVIDER_TYPE: Final = "webauthn"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.webauthn"

SIGN_IN_TIMEOUT_MS: Final = 60000
REGISTER_TIMEOUT_MS: Final = 60000

CONF_RP_NAME: Final = "rp_name"
CONF_AUTHENTICATION_CREDENTIAL: Final = "authentication_credential"
CONF_USER_ID: Final = "user_id"


def _disallow_id(conf: dict[str, Any]) -> dict[str, Any]:
    """Disallow ID in config."""
    if CONF_ID in conf:
        raise vol.Invalid("ID is not allowed for the webauthn auth provider.")

    return conf


CONFIG_SCHEMA = vol.All(
    AUTH_PROVIDER_SCHEMA.extend(
        {
            vol.Optional(CONF_RP_NAME, default="Home Assistant"): str,
        }
    ),
    _disallow_id,
)


class _RelyingParty(NamedTuple):
    """Relying party a WebAuthn ceremony runs for."""

    id: str
    origin: str


@callback
def _async_relying_party(hass: HomeAssistant, origin: str) -> _RelyingParty:
    """Return the relying party to run a ceremony for.

    WebAuthn only runs in a secure context and cannot use an IP address as
    relying party, so anything else is rejected before a ceremony starts.
    """
    url = yarl.URL(origin).origin()

    if url.scheme != "https" or url.host is None or is_ip_address(url.host):
        raise InvalidAuthError(f"Cannot use {origin} for WebAuthn.")

    if not is_hass_url(hass, str(url)):
        raise InvalidAuthError(f"{origin} is not a known Home Assistant URL.")

    return _RelyingParty(url.host, str(url))


@callback
def async_get_provider(hass: HomeAssistant) -> WebAuthnProvider:
    """Get the provider."""
    for prv in hass.auth.auth_providers:
        if prv.type == WEBAUTHN_PROVIDER_TYPE:
            return cast(WebAuthnProvider, prv)
    raise RuntimeError("Provider not found")


@dataclass(kw_only=True)
class WebAuthnCredentialMeta:
    """Class to hold WebAuthn credential metadata."""

    credential_id: str
    name: str = "Passkey"
    created_at: float = field(default_factory=time)
    last_used_at: float = field(default_factory=time)


@dataclass(kw_only=True)
class WebAuthnCredential(WebAuthnCredentialMeta):
    """Class to hold WebAuthn registration data."""

    credential_public_key: str
    sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool


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
        self, user_id: str, credential: WebAuthnCredential
    ) -> None:
        """Store data to persistent storage."""

        user_creds = self._data.setdefault(user_id, {})
        user_creds[credential.credential_id] = credential
        await self._store.async_save(self._data)

    async def async_delete_credential(self, user_id: str, credential_id: str) -> None:
        """Delete credential from persistent storage."""
        if self._data.get(user_id, {}).pop(credential_id, None) is None:
            raise CredentialNotFoundError("Credential not found.")
        await self._store.async_save(self._data)

    async def async_rename_credential(
        self, user_id: str, credential_id: str, new_name: str
    ) -> None:
        """Rename credential in persistent storage."""
        if (credential := self._data.get(user_id, {}).get(credential_id)) is None:
            raise CredentialNotFoundError("Credential not found.")
        credential.name = new_name
        await self._store.async_save(self._data)

    async def async_delete_user_credentials(self, user_id: str) -> None:
        """Delete all credentials of a user from persistent storage."""
        if self._data.pop(user_id, None) is None:
            return
        await self._store.async_save(self._data)

    async def async_update_user_registration(
        self,
        user_id: str,
        credential_id: str,
        new_sign_count: int,
        credential_device_type: CredentialDeviceType,
        credential_backed_up: bool,
    ) -> None:
        """Update credential data in after a successful authentication."""
        if registration := self._data.get(user_id, {}).get(credential_id):
            registration.sign_count = new_sign_count
            registration.credential_device_type = credential_device_type
            registration.credential_backed_up = credential_backed_up
            registration.last_used_at = time()
            await self._store.async_save(self._data)

    def get_registered_credentials(
        self, user_id: str
    ) -> list[PublicKeyCredentialDescriptor]:
        """Retrieve allowed credentials for a user."""
        return [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in self._data.get(user_id, {})
        ]

    def get_credential(
        self, user_id: str, credential_id: str
    ) -> WebAuthnCredential | None:
        """Retrieve data from persistent storage."""

        return self._data.get(user_id, {}).get(credential_id)

    def list_credentials_meta(self, user_id: str) -> list[WebAuthnCredentialMeta]:
        """Retrieve the metadata of registered credentials for a user."""
        return [
            WebAuthnCredentialMeta(
                credential_id=cred.credential_id,
                name=cred.name,
                created_at=cred.created_at,
                last_used_at=cred.last_used_at,
            )
            for cred in self._data.get(user_id, {}).values()
        ]


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

        # store the challenges for pending registrations for each user
        self._pending_registration_challenges: dict[str, bytes] = {}

        self._init_lock = Lock()
        self._registration_lock = Lock()

    @property
    @override
    def support_mfa(self) -> bool:
        """Return whether multi-factor auth supported by the auth provider.

        Passkeys are registered and verified with user verification required, so
        the authenticator has already checked both possession of the device and a
        biometric or PIN. Asking for another factor on top would be redundant.
        """
        return False

    @override
    async def async_initialize(self) -> None:
        """Initialize the auth provider."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = WebAuthnDataStore(self.hass)
            await data.async_load()
            self.data = data

    async def _async_get_data(self) -> WebAuthnDataStore:
        """Return the data store, loading it if needed."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        return self.data

    @override
    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> WebAuthnLoginFlow:
        """Return a flow to login."""
        return WebAuthnLoginFlow(self)

    async def async_start_registration(
        self, user: User, origin: str
    ) -> PublicKeyCredentialCreationOptions:
        """Register a new WebAuthn credential."""

        data = await self._async_get_data()
        relying_party = _async_relying_party(self.hass, origin)

        options = generate_registration_options(
            rp_name=self.config[CONF_RP_NAME],
            rp_id=relying_party.id,
            # The authenticator hands this back as the user handle on login,
            # which is how a passkey identifies its account.
            user_id=user.id.encode(),
            # Only ever shown in the authenticator's account picker.
            user_name=user.name or user.id,
            exclude_credentials=data.get_registered_credentials(user.id),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            timeout=REGISTER_TIMEOUT_MS,
        )

        async with self._registration_lock:
            self._pending_registration_challenges[user.id] = options.challenge

        self._async_remove_pending_challenge_later(user.id, options.challenge)
        return options

    async def async_verify_registration(
        self, user: User, credential: dict[str, Any], origin: str
    ) -> None:
        """Complete the registration of a new WebAuthn credential."""
        async with self._registration_lock:
            challenge = self._pending_registration_challenges.pop(user.id, None)

        if challenge is None:
            raise InvalidAuthError("No pending registration found for user.")

        relying_party = _async_relying_party(self.hass, origin)

        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=relying_party.id,
                expected_origin=relying_party.origin,
                require_user_verification=True,
            )
        except WebAuthnException as err:
            raise InvalidAuthError("Registration failed.") from err

        data = await self._async_get_data()

        web_authn_credential = WebAuthnCredential(
            credential_id=bytes_to_base64url(verification.credential_id),
            credential_public_key=bytes_to_base64url(
                verification.credential_public_key
            ),
            sign_count=verification.sign_count,
            credential_device_type=verification.credential_device_type,
            credential_backed_up=verification.credential_backed_up,
        )

        await data.async_add_credential(user.id, web_authn_credential)
        await self._async_link_credentials(user)

    async def _async_link_credentials(self, user: User) -> None:
        """Give the user credentials for this provider if they have none yet."""
        if self._async_user_credentials(user) is not None:
            return

        await self.hass.auth.async_link_user(
            user, self.async_create_credentials({CONF_USER_ID: user.id})
        )

    @callback
    def _async_user_credentials(self, user: User) -> Credentials | None:
        """Return the credentials the user has for this provider."""
        for credential in user.credentials:
            if (
                credential.auth_provider_type == self.type
                and credential.auth_provider_id == self.id
            ):
                return credential

        return None

    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """Drop the stored passkeys when the credentials are removed."""
        data = await self._async_get_data()
        await data.async_delete_user_credentials(credentials.data[CONF_USER_ID])

    async def async_start_authentication(
        self, origin: str
    ) -> PublicKeyCredentialRequestOptions:
        """Start the authentication process."""

        return generate_authentication_options(
            rp_id=_async_relying_party(self.hass, origin).id,
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=SIGN_IN_TIMEOUT_MS,
        )

    async def async_verify_authentication(
        self, credential: dict[str, Any], challenge: bytes, origin: str
    ) -> str:
        """Complete the authentication process and return the ID of the user."""

        try:
            parsed = parse_authentication_credential_json(credential)
        except WebAuthnException as err:
            raise InvalidAuthError("Malformed credential.") from err

        if (user_handle := parsed.response.user_handle) is None:
            raise InvalidAuthError("Credential is not discoverable.")

        try:
            user_id = user_handle.decode()
        except UnicodeDecodeError as err:
            raise InvalidAuthError("Invalid user handle.") from err

        data = await self._async_get_data()
        relying_party = _async_relying_party(self.hass, origin)

        registration = data.get_credential(user_id, parsed.id)
        if registration is None:
            raise InvalidAuthError("No registered credentials found for user.")

        try:
            response = verify_authentication_response(
                credential=parsed,
                expected_challenge=challenge,
                expected_rp_id=relying_party.id,
                expected_origin=relying_party.origin,
                credential_public_key=base64url_to_bytes(
                    registration.credential_public_key
                ),
                credential_current_sign_count=registration.sign_count,
                require_user_verification=True,
            )
        except WebAuthnException as err:
            raise InvalidAuthError("Authentication failed.") from err

        # Update the sign count and other info
        await data.async_update_user_registration(
            user_id=user_id,
            credential_id=bytes_to_base64url(response.credential_id),
            new_sign_count=response.new_sign_count,
            credential_device_type=response.credential_device_type,
            credential_backed_up=response.credential_backed_up,
        )
        return user_id

    async def async_delete_credential(self, user: User, credential_id: str) -> None:
        """Delete a registered credential."""
        data = await self._async_get_data()
        await data.async_delete_credential(user.id, credential_id)

        # Without a passkey left to sign in with, the credentials are dead weight.
        if not data.get_registered_credentials(user.id) and (
            credentials := self._async_user_credentials(user)
        ):
            await self.hass.auth.async_remove_credentials(credentials)

    async def async_list_credentials_meta(
        self, user_id: str
    ) -> list[WebAuthnCredentialMeta]:
        """List all registered credentials for a user."""
        data = await self._async_get_data()
        return data.list_credentials_meta(user_id)

    async def async_rename_credential(
        self,
        user_id: str,
        credential_id: str,
        new_name: str,
    ) -> None:
        """Rename a registered credential for a user."""
        data = await self._async_get_data()
        await data.async_rename_credential(user_id, credential_id, new_name)

    @override
    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""

        user_id = flow_result[CONF_USER_ID]

        for credential in await self.async_credentials():
            if credential.data[CONF_USER_ID] == user_id:
                return credential

        # Credentials are created when the user registers their first passkey.
        raise InvalidAuthError("No credentials found for user.")

    @override
    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        A passkey can only be registered by an existing user, so this provider
        never creates one.
        """

        raise NotImplementedError

    @callback
    def _async_remove_pending_challenge_later(
        self, user_id: str, challenge: bytes
    ) -> None:
        """Remove a pending registration challenge for a user after a timeout."""

        async def remove_challenge(_: Any) -> None:
            async with self._registration_lock:
                if self._pending_registration_challenges.get(user_id) == challenge:
                    self._pending_registration_challenges.pop(user_id)

        async_call_later(
            self.hass,
            REGISTER_TIMEOUT_MS / 1000,
            remove_challenge,
        )


class WebAuthnLoginFlow(LoginFlow[WebAuthnProvider]):
    """Handler for the login flow."""

    _challenge: bytes
    _challenge_expires_at: float

    @override
    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Initialize the login flow."""

        errors: dict[str, str] = {}
        # Verified against the client ID before the flow is started.
        if (redirect_uri := self.context.get("redirect_uri")) is None:
            raise InvalidAuthError("Flow was started without a redirect URI.")

        if user_input is not None:
            # The timeout in the options is only a hint to the client, so the
            # challenge lifetime has to be enforced here as well.
            if time() > self._challenge_expires_at:
                errors["base"] = "invalid_auth"
            else:
                try:
                    user_id = await self._auth_provider.async_verify_authentication(
                        user_input[CONF_AUTHENTICATION_CREDENTIAL],
                        self._challenge,
                        redirect_uri,
                    )
                except InvalidAuthError:
                    errors["base"] = "invalid_auth"
                else:
                    return await self.async_finish({CONF_USER_ID: user_id})

        options = await self._auth_provider.async_start_authentication(redirect_uri)
        self._challenge = options.challenge
        self._challenge_expires_at = time() + SIGN_IN_TIMEOUT_MS / 1000
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_AUTHENTICATION_CREDENTIAL): dict,
                }
            ),
            description_placeholders={"webauthn_options": options_to_json(options)},
            errors=errors,
        )
