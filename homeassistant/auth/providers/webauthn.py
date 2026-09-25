"""WebAuthn authentication provider for Home Assistant."""

from asyncio import Lock
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import logging
from time import time
from typing import Any, Final, NamedTuple, cast, override

import probatio
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
from webauthn.helpers.options_to_json_dict import options_to_json_dict
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
from homeassistant.helpers.network import is_hass_url
from homeassistant.helpers.storage import Store
from homeassistant.util.network import is_ip_address

from ..auth_store import AuthStore
from ..models import AuthFlowContext, AuthFlowResult, Credentials, User, UserMeta
from . import (
    AUTH_PROVIDER_SCHEMA,
    AUTH_PROVIDERS,
    AuthProvider,
    InvalidStepUpError,
    LoginFlow,
)

REQUIREMENTS = ["webauthn==3.0.0"]

_LOGGER = logging.getLogger(__name__)

WEBAUTHN_PROVIDER_TYPE: Final = "webauthn"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.webauthn"

SIGN_IN_TIMEOUT_MS: Final = 60000
REGISTER_TIMEOUT_MS: Final = 60000

CONF_RP_NAME: Final = "rp_name"
CONF_AUTHENTICATION_CREDENTIAL: Final = "authentication_credential"
CONF_USER_ID: Final = "user_id"

DEFAULT_CREDENTIAL_NAME: Final = "Passkey"


def _disallow_id(conf: dict[str, Any]) -> dict[str, Any]:
    """Disallow ID in config."""
    if CONF_ID in conf:
        raise probatio.Invalid("ID is not allowed for the webauthn auth provider.")

    return conf


CONFIG_SCHEMA = probatio.All(
    AUTH_PROVIDER_SCHEMA.extend(
        {
            probatio.Optional(CONF_RP_NAME, default="Home Assistant"): str,
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
    """Return the relying party for an origin, which must be HTTPS and not an IP."""
    try:
        url = yarl.URL(origin).origin()
    except ValueError as err:
        raise InvalidAuthError(f"Cannot use {origin} for WebAuthn.") from err

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
    rp_id: str
    name: str = DEFAULT_CREDENTIAL_NAME
    created_at: float = field(default_factory=time)
    last_used_at: float = field(default_factory=time)


@dataclass(kw_only=True)
class WebAuthnCredential(WebAuthnCredentialMeta):
    """Class to hold WebAuthn registration data."""

    credential_public_key: str
    sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool

    def __post_init__(self) -> None:
        """Restore the device type, which is stored as a plain string."""
        self.credential_device_type = CredentialDeviceType(self.credential_device_type)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


class CredentialNotFoundError(HomeAssistantError):
    """Raised when submitting invalid credential."""


class CredentialAlreadyRegisteredError(HomeAssistantError):
    """Raised when a credential ID is already registered."""


class LastLoginMethodError(HomeAssistantError):
    """Raised when deleting a credential would lock the user out."""


type DataType = dict[str, dict[str, WebAuthnCredential]]


class WebAuthnDataStore:
    """Class to hold WebAuthn related data."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize WebAuthn data."""
        # Credentials round trip through JSON as plain dicts.
        self._store = Store[dict[str, dict[str, dict[str, Any]]]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: DataType = {}

    async def async_load(self) -> None:
        """Load data from persistent storage."""
        if (data := await self._store.async_load()) is None:
            data = {}

        self._data = {
            user_id: {
                credential_id: WebAuthnCredential(**credential)
                for credential_id, credential in credentials.items()
            }
            for user_id, credentials in data.items()
        }

    async def _async_save(self) -> None:
        """Write the credentials back to persistent storage."""
        await self._store.async_save(
            {
                user_id: {
                    credential_id: asdict(credential)
                    for credential_id, credential in credentials.items()
                }
                for user_id, credentials in self._data.items()
            }
        )

    async def async_add_credential(
        self, user_id: str, credential: WebAuthnCredential
    ) -> None:
        """Store data to persistent storage."""

        # A credential ID registered to any user must be rejected, and nothing
        # awaits between the check and the insert, so registrations cannot race.
        if any(
            credential.credential_id in credentials
            for credentials in self._data.values()
        ):
            raise CredentialAlreadyRegisteredError("Credential is already registered.")

        user_creds = self._data.setdefault(user_id, {})
        user_creds[credential.credential_id] = credential
        await self._async_save()

    async def async_delete_credential(self, user_id: str, credential_id: str) -> None:
        """Delete credential from persistent storage."""
        if self._data.get(user_id, {}).pop(credential_id, None) is None:
            raise CredentialNotFoundError("Credential not found.")
        await self._async_save()

    async def async_rename_credential(
        self, user_id: str, credential_id: str, new_name: str
    ) -> None:
        """Rename credential in persistent storage."""
        if (credential := self._data.get(user_id, {}).get(credential_id)) is None:
            raise CredentialNotFoundError("Credential not found.")
        credential.name = new_name
        await self._async_save()

    async def async_delete_user_credentials(self, user_id: str) -> None:
        """Delete all credentials of a user from persistent storage."""
        if self._data.pop(user_id, None) is None:
            return
        await self._async_save()

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
            await self._async_save()

    @property
    def has_credentials(self) -> bool:
        """Return if anybody has registered a passkey."""
        return any(self._data.values())

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
                rp_id=cred.rp_id,
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
        # Challenge and deadline of each user's pending ceremony.
        self._pending_registration_challenges: dict[str, tuple[bytes, float]] = {}
        self._pending_step_up_challenges: dict[str, tuple[bytes, float]] = {}
        self._init_lock = Lock()

    @property
    @override
    def support_mfa(self) -> bool:
        """Return False, as user verification already covers a second factor."""
        return False

    @property
    @override
    def support_step_up(self) -> bool:
        """Return that a signed in user can re-verify with a passkey."""
        return True

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

    @callback
    @override
    def async_can_start_login(self, context: AuthFlowContext) -> bool:
        """Return if anybody has a passkey to sign in with."""
        return self.data is not None and self.data.has_credentials

    async def async_start_registration(
        self, user: User, origin: str
    ) -> PublicKeyCredentialCreationOptions:
        """Register a new WebAuthn credential."""

        data = await self._async_get_data()
        relying_party = _async_relying_party(self.hass, origin)

        options = generate_registration_options(
            rp_name=self.config[CONF_RP_NAME],
            rp_id=relying_party.id,
            # Returned as the user handle on login, identifying the account.
            user_id=user.id.encode(),
            user_name=user.name or user.id,
            exclude_credentials=data.get_registered_credentials(user.id),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            timeout=REGISTER_TIMEOUT_MS,
        )

        self._pending_registration_challenges[user.id] = (
            options.challenge,
            time() + REGISTER_TIMEOUT_MS / 1000,
        )

        _LOGGER.debug(
            "Registration options for %s: %s", user.id, options_to_json(options)
        )
        return options

    async def async_verify_registration(
        self,
        user: User,
        credential: dict[str, Any],
        origin: str,
        name: str | None = None,
    ) -> None:
        """Complete the registration of a new WebAuthn credential."""
        pending = self._pending_registration_challenges.pop(user.id, None)
        # The timeout in the options is only a hint to the client.
        if pending is None or time() > pending[1]:
            raise InvalidAuthError("No pending registration found for user.")
        challenge = pending[0]

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
            name=name or DEFAULT_CREDENTIAL_NAME,
            rp_id=relying_party.id,
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

    @override
    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """Drop the stored passkeys when the credentials are removed."""
        await self.hass.auth.async_remove_refresh_tokens_for_credentials(credentials)

        data = await self._async_get_data()
        await data.async_delete_user_credentials(credentials.data[CONF_USER_ID])

    async def async_start_authentication(
        self, origin: str
    ) -> PublicKeyCredentialRequestOptions:
        """Start the authentication process."""

        options = generate_authentication_options(
            rp_id=_async_relying_party(self.hass, origin).id,
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=SIGN_IN_TIMEOUT_MS,
        )
        _LOGGER.debug("Authentication options: %s", options_to_json(options))
        return options

    async def async_verify_authentication(
        self, credential: str | dict[str, Any], challenge: bytes, origin: str
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

    @override
    async def async_start_step_up(
        self, user: User, context: AuthFlowContext | None
    ) -> dict[str, Any]:
        """Return the options the client needs to build a passkey proof."""
        origin = context.get("origin") if context else None
        if origin is None:
            raise InvalidAuthError("No origin to run a WebAuthn ceremony for.")

        data = await self._async_get_data()
        options = generate_authentication_options(
            rp_id=_async_relying_party(self.hass, origin).id,
            # The user is known here, so only their own passkeys are offered.
            allow_credentials=data.get_registered_credentials(user.id),
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=SIGN_IN_TIMEOUT_MS,
        )
        self._pending_step_up_challenges[user.id] = (
            options.challenge,
            time() + SIGN_IN_TIMEOUT_MS / 1000,
        )
        return options_to_json_dict(options)

    @override
    async def async_verify_step_up(
        self, user: User, data: Mapping[str, Any], context: AuthFlowContext | None
    ) -> None:
        """Verify a passkey proof from an already signed in user."""
        origin = context.get("origin") if context else None
        if origin is None:
            raise InvalidStepUpError("No origin to verify a passkey against.")

        challenge = self._pending_step_up_challenges.pop(user.id, None)
        # The timeout in the options is only a hint to the client.
        if challenge is None or time() > challenge[1]:
            raise InvalidStepUpError("No pending step up challenge for user.")

        if (credential := data.get(CONF_AUTHENTICATION_CREDENTIAL)) is None:
            raise InvalidStepUpError("No credential to verify.")

        try:
            verified_user_id = await self.async_verify_authentication(
                credential, challenge[0], origin
            )
        except InvalidAuthError as err:
            raise InvalidStepUpError("Passkey step up failed.") from err

        # A passkey proves whoever holds it, so it has to be one of this user's.
        if verified_user_id != user.id:
            raise InvalidStepUpError("Passkey does not belong to this user.")

    async def async_delete_credential(self, user: User, credential_id: str) -> None:
        """Delete a registered credential."""
        data = await self._async_get_data()

        credentials = self._async_user_credentials(user)
        if (
            data.get_credential(user.id, credential_id) is not None
            and len(data.get_registered_credentials(user.id)) == 1
            and credentials is not None
            and not self.hass.auth.async_has_other_login_method(user, credentials)
        ):
            raise LastLoginMethodError(
                "Cannot delete the last passkey without another way to log in."
            )

        await data.async_delete_credential(user.id, credential_id)

        # Every passkey shares one credential, so a session cannot be traced back
        # to the key it was created with and they all have to go.
        if credentials is not None:
            await self.hass.auth.async_remove_refresh_tokens_for_credentials(
                credentials
            )

        # Without a passkey left to sign in with, the credentials are dead weight.
        if not data.get_registered_credentials(user.id) and credentials is not None:
            await self.hass.auth.async_remove_credentials(credentials)

    async def async_list_credentials_meta(
        self, user: User
    ) -> list[WebAuthnCredentialMeta]:
        """List all registered credentials for a user."""
        data = await self._async_get_data()
        return data.list_credentials_meta(user.id)

    async def async_rename_credential(
        self,
        user: User,
        credential_id: str,
        new_name: str,
    ) -> None:
        """Rename a registered credential for a user."""
        data = await self._async_get_data()
        await data.async_rename_credential(user.id, credential_id, new_name)

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
        """Refuse, as only an existing user can register a passkey."""
        raise NotImplementedError


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
        # Client supplied, so the origin is checked again for every ceremony.
        if (origin := self.context.get("origin")) is None:
            return self.async_abort(reason="missing_origin")

        if user_input is not None:
            # The timeout in the options is only a hint to the client.
            if time() > self._challenge_expires_at:
                _LOGGER.debug("Passkey login rejected: challenge expired")
                errors["base"] = "invalid_auth"
            else:
                try:
                    user_id = await self._auth_provider.async_verify_authentication(
                        user_input[CONF_AUTHENTICATION_CREDENTIAL],
                        self._challenge,
                        origin,
                    )
                    credentials = (
                        await self._auth_provider.async_get_or_create_credentials(
                            {CONF_USER_ID: user_id}
                        )
                    )
                except InvalidAuthError as err:
                    _LOGGER.debug("Passkey login rejected: %s", err, exc_info=True)
                    errors["base"] = "invalid_auth"
                else:
                    return await self.async_finish(credentials)

        try:
            options = await self._auth_provider.async_start_authentication(origin)
        except InvalidAuthError as err:
            _LOGGER.debug("Cannot offer a passkey login: %s", err)
            return self.async_abort(reason="invalid_origin")

        self._challenge = options.challenge
        self._challenge_expires_at = time() + SIGN_IN_TIMEOUT_MS / 1000
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema(
                {
                    probatio.Required(CONF_AUTHENTICATION_CREDENTIAL): str,
                }
            ),
            description_placeholders={"webauthn_options": options_to_json(options)},
            errors=errors,
        )
