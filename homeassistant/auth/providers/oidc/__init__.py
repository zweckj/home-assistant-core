"""OpenID Connect identity provider engine."""

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
import logging
import secrets
from typing import Any, override
from weakref import WeakValueDictionary

import probatio

from homeassistant.const import CONF_ID
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.network import (
    NoURLAvailableError,
    get_url,
    is_internal_request,
)
from homeassistant.helpers.oauth2 import generate_code_verifier

from ... import InvalidAuthError
from ...const import LOGIN_CALLBACK_PATH
from ...models import (
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    RefreshToken,
    User,
    UserMeta,
)
from .. import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, MfaLoginFlow
from .client import (
    OidcClient,
    OidcError,
    OidcInsecureTransportError,
    OidcTransientError,
    ProviderMetadata,
    async_discover,
)
from .const import CONF_ISSUER, CONF_SUBJECT, PROVIDER_TYPE
from .spec import (
    IdentityProvider,
    IdentityProviderError,
    OpenIDConnect,
    trust_key,
    validate_identity_provider,
)
from .store import IdentityProviderRecord, OidcStore

_LOGGER = logging.getLogger(__name__)

CONF_ACCOUNT_NAME = "account_name"

__all__ = [
    "IdentityProvider",
    "IdentityProviderError",
    "OidcAuthProvider",
    "OidcIdentityProvider",
    "OpenIDConnect",
    "ProviderMetadata",
    "async_discover_identity_provider",
    "async_get_provider",
    "async_validate_identity_provider",
    "trust_key",
    "validate_identity_provider",
]


def _disallow_id(conf: dict[str, Any]) -> dict[str, Any]:
    """Disallow ID in config."""
    if CONF_ID in conf:
        raise probatio.Invalid("ID is not allowed for the oidc auth provider.")
    return conf


CONFIG_SCHEMA = probatio.All(AUTH_PROVIDER_SCHEMA, _disallow_id)


@callback
def async_get_provider(hass: HomeAssistant) -> OidcAuthProvider | None:
    """Get the OIDC engine root provider."""
    provider = hass.auth.get_auth_provider(PROVIDER_TYPE, None)
    return provider if isinstance(provider, OidcAuthProvider) else None


def _claim_as_str(value: Any) -> str | None:
    """Return a claim that has to be a string."""
    return value if isinstance(value, str) else None


def _build_client(hass: HomeAssistant, spec: IdentityProvider) -> OidcClient:
    """Return the protocol client for a validated spec."""
    try:
        return OidcClient(
            hass,
            issuer=spec.protocol.issuer,
            client_id=spec.client_id,
            client_secret=spec.client_secret,
        )
    except OidcError as err:
        raise IdentityProviderError("invalid_spec", str(err)) from err


@contextmanager
def _discovery_errors() -> Iterator[None]:
    """Translate discovery failures into stable validation reasons."""
    try:
        yield
    except OidcTransientError as err:
        raise IdentityProviderError("cannot_connect", str(err)) from err
    except OidcError as err:
        raise IdentityProviderError("invalid_discovery", str(err)) from err


async def async_discover_identity_provider(
    hass: HomeAssistant, discovery_url: str
) -> ProviderMetadata:
    """Fetch and validate an OpenID Connect discovery document."""
    with _discovery_errors():
        return await async_discover(hass, discovery_url)


async def async_validate_identity_provider(
    hass: HomeAssistant, spec: IdentityProvider
) -> IdentityProvider:
    """Validate a spec the way registration does, and reach its discovery document."""
    validated = validate_identity_provider(spec)
    client = _build_client(hass, validated)
    with _discovery_errors():
        await client.async_metadata()
    return validated


@AUTH_PROVIDERS.register(PROVIDER_TYPE)
class OidcAuthProvider(AuthProvider):
    """Root provider for the identity provider engine."""

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the provider."""
        super().__init__(*args, **kwargs)
        self.data: OidcStore | None = None
        self._init_lock = asyncio.Lock()
        self._config_lock = asyncio.Lock()
        self._children: dict[str, OidcIdentityProvider] = {}

    @property
    @override
    def child_providers(self) -> Iterable[AuthProvider]:
        """Return child identity providers."""
        return tuple(self._children.values())

    @callback
    @override
    def async_get_child_provider(self, provider_id: str) -> AuthProvider | None:
        """Return a child identity provider."""
        return self._children.get(provider_id)

    @property
    def identity_provider_ids(self) -> frozenset[str]:
        """Return registered identity provider IDs."""
        if self.data is None:
            return frozenset()
        return frozenset(self.data.records)

    @callback
    @override
    def async_can_start_login(self, context: AuthFlowContext) -> bool:
        """Return that the root is hidden from login."""
        return False

    @override
    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> OidcRootLoginFlow:
        """Return a root flow that aborts."""
        return OidcRootLoginFlow(self)

    @override
    async def async_initialize(self) -> None:
        """Load the stored registry and create a dormant child per record."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = OidcStore(self.hass)
            await data.async_load()
            self.data = data
            for record in data.records.values():
                self._async_child_for_record(record)

    @property
    def config_lock(self) -> asyncio.Lock:
        """Return the provider configuration lock."""
        return self._config_lock

    async def async_get_data(self) -> OidcStore:
        """Return the data store, loading it if needed."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None
        return self.data

    @callback
    def _async_child_for_record(
        self, record: IdentityProviderRecord
    ) -> OidcIdentityProvider:
        """Return or create a child for a registry record."""
        child = self._children.get(record.idp_id)
        if child is None:
            child = OidcIdentityProvider(self, record)
            self._children[record.idp_id] = child
        return child

    async def async_register_identity_provider(
        self, idp_id: str, *, domain: str, title: str, spec: IdentityProvider
    ) -> None:
        """Register or activate an identity provider."""
        if not idp_id or not domain or not title:
            raise IdentityProviderError("invalid_idp")
        validated = validate_identity_provider(spec)
        client = _build_client(self.hass, validated)
        key = trust_key(validated)
        data = await self.async_get_data()

        async with self._config_lock:
            record = data.records.get(idp_id)
            if record is not None and record.trust_key != key:
                await self.async_end_identity_provider_sessions(idp_id)
            record = IdentityProviderRecord(idp_id=idp_id, domain=domain, trust_key=key)
            data.async_set_record(record)
            child = self._async_child_for_record(record)
            child.async_activate(
                title=title, spec=validated, record=record, client=client
            )

    @callback
    def async_suspend_identity_provider(self, idp_id: str) -> None:
        """Suspend an unloaded or failed identity provider entry."""
        if child := self._children.get(idp_id):
            child.async_suspend()

    async def async_end_identity_provider_sessions(self, idp_id: str) -> None:
        """End Home Assistant sessions signed in through an identity provider."""
        if (child := self._children.get(idp_id)) is None:
            return
        for credentials in await child.async_credentials():
            await self.hass.auth.async_remove_refresh_tokens_for_credentials(
                credentials
            )

    async def async_remove_identity_provider(self, idp_id: str) -> list[User]:
        """Remove an identity provider and its credentials."""
        data = await self.async_get_data()
        removed_users: list[User] = []
        async with self._config_lock:
            # Suspending first makes logins still in flight abort.
            child = self._children.get(idp_id)
            if child is not None:
                child.async_suspend()
        if child is not None:
            credentials = await child.async_credentials()
            credentials_by_user: dict[str, list[Credentials]] = {}
            for user in await self.store.async_get_users():
                owned = [cred for cred in credentials if cred in user.credentials]
                if not owned:
                    continue
                credentials_by_user[user.id] = owned
                if not self.hass.auth.async_has_other_login_method(user, *owned):
                    removed_users.append(user)

            await self.async_end_identity_provider_sessions(idp_id)
            for owned in credentials_by_user.values():
                for credential in owned:
                    await self.hass.auth.async_remove_credentials(credential)

        data.async_remove_record(idp_id)
        self._children.pop(idp_id, None)
        return removed_users


class OidcIdentityProvider(AuthProvider):
    """Child identity provider served by the OIDC engine."""

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(self, root: OidcAuthProvider, record: IdentityProviderRecord) -> None:
        """Initialize the child provider."""
        super().__init__(
            root.hass, root.store, {"type": PROVIDER_TYPE, CONF_ID: record.idp_id}
        )
        self.root = root
        self.record = record
        self._title: str | None = None
        self._spec: IdentityProvider | None = None
        self._client: OidcClient | None = None
        self._generation = 0
        self._pending_credentials: WeakValueDictionary[tuple[str, str], Credentials] = (
            WeakValueDictionary()
        )

    @property
    def active(self) -> bool:
        """Return if the child has a runtime spec and can start logins."""
        return self._spec is not None

    @property
    def generation(self) -> int:
        """Return the configuration generation."""
        return self._generation

    @property
    def spec(self) -> IdentityProvider:
        """Return the active runtime spec."""
        if self._spec is None:
            raise OidcError("The identity provider is dormant")
        return self._spec

    @property
    @override
    def name(self) -> str:
        """Return the runtime title or a dormant fallback."""
        return self._title or self.DEFAULT_TITLE

    @property
    @override
    def domain(self) -> str | None:
        """Return the brand domain for this child."""
        return self.record.domain

    @callback
    def async_activate(
        self,
        *,
        title: str,
        spec: IdentityProvider,
        record: IdentityProviderRecord,
        client: OidcClient,
    ) -> None:
        """Activate the child with a runtime spec."""
        self.record = record
        self._title = title
        self._spec = spec
        self._client = client
        self._generation += 1
        self._pending_credentials.clear()

    @callback
    def async_suspend(self) -> None:
        """Make the child dormant."""
        self._spec = None
        self._client = None
        self._generation += 1
        self._pending_credentials.clear()

    @callback
    @override
    def async_can_start_login(self, context: AuthFlowContext) -> bool:
        """Return if this identity provider is active."""
        return self.active

    @callback
    @override
    def async_can_login_with_credentials(self, credentials: Credentials) -> bool:
        """Return if these credentials are usable as a fallback login."""
        return (
            self._client is not None
            and credentials.data.get(CONF_ISSUER) == self._client.issuer
        )

    @callback
    def async_redirect_uri(self) -> str:
        """Return the redirect URI, refusing plain HTTP reachable from outside."""
        url = get_url(self.hass, require_current_request=True)
        if not url.startswith("https://") and not is_internal_request(self.hass):
            raise OidcInsecureTransportError(
                f"Signing in through {url} would expose the tokens, use HTTPS"
            )
        return f"{url}{LOGIN_CALLBACK_PATH}"

    @callback
    def async_client(self) -> OidcClient:
        """Return the protocol client of the active identity provider."""
        if self._client is None:
            raise OidcError("The identity provider is dormant")
        return self._client

    @asynccontextmanager
    async def async_config_guard(self, generation: int) -> AsyncIterator[bool]:
        """Guard side effects against concurrent provider reconfiguration."""
        async with self.root.config_lock:
            yield self.active and self.generation == generation

    @override
    async def async_login_flow(self, context: AuthFlowContext | None) -> OidcLoginFlow:
        """Return a flow to login."""
        return OidcLoginFlow(self)

    @override
    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        issuer = flow_result[CONF_ISSUER]
        subject = flow_result[CONF_SUBJECT]
        account_name = flow_result.get(CONF_ACCOUNT_NAME)
        identity = (issuer, subject)
        data = {CONF_ISSUER: issuer, CONF_SUBJECT: subject}
        if account_name is not None:
            data[CONF_ACCOUNT_NAME] = account_name

        for credentials in await self.async_credentials():
            if (
                credentials.data.get(CONF_ISSUER) == issuer
                and credentials.data.get(CONF_SUBJECT) == subject
            ):
                self._pending_credentials.pop(identity, None)
                if credentials.data.get(CONF_ACCOUNT_NAME) != account_name:
                    self.hass.auth.async_update_user_credentials_data(credentials, data)
                return credentials

        if (pending := self._pending_credentials.get(identity)) is None:
            pending = self.async_create_credentials(data)
            self._pending_credentials[identity] = pending
        return pending

    @override
    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Refuse to create users, identities may only be linked."""
        raise InvalidAuthError("The identity provider may only link users")

    @override
    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """End the sessions of credentials that are removed."""
        await self.hass.auth.async_remove_refresh_tokens_for_credentials(credentials)

    @callback
    @override
    def async_validate_refresh_token(
        self, refresh_token: RefreshToken, remote_ip: str | None = None
    ) -> None:
        """Refuse a code minted before suspension as the start of a new session."""
        if refresh_token.last_used_at is None and not self.active:
            raise InvalidAuthError("Sign in with the identity provider again")


class OidcRootLoginFlow(MfaLoginFlow[OidcAuthProvider]):
    """Root login flow, never configured for direct login."""

    @override
    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Abort root login attempts."""
        return self.async_abort(reason="not_configured")


class OidcLoginFlow(MfaLoginFlow[OidcIdentityProvider]):
    """Handler for child identity provider login flows."""

    def __init__(self, auth_provider: OidcIdentityProvider) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._code_verifier = generate_code_verifier()
        self._nonce = secrets.token_urlsafe(32)
        self._redirect_uri: str | None = None
        self._code: str | None = None
        self._error: str | None = None
        self._generation: int | None = None
        self._client: OidcClient | None = None
        self._protocol: OpenIDConnect | None = None

    @override
    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Send the user to the identity provider."""
        provider = self._auth_provider
        if not provider.active:
            return self.async_abort(reason="not_configured")

        try:
            self._redirect_uri = provider.async_redirect_uri()
        except NoURLAvailableError:
            return self.async_abort(reason="no_url_available")
        except OidcInsecureTransportError as err:
            _LOGGER.error("Refusing to start an OIDC login: %s", err)
            return self.async_abort(reason="insecure_transport")

        # Captured together, before any await, so the finish step can tell
        # whether the identity provider was reconfigured in between.
        self._generation = provider.generation
        self._client = client = provider.async_client()
        self._protocol = protocol = provider.spec.protocol
        state = self._auth_manager.login_flow.async_encode_external_state(self.flow_id)
        try:
            metadata = await client.async_metadata()
        except OidcError as err:
            _LOGGER.error("Could not reach the identity provider: %s", err)
            return self.async_abort(reason="provider_unavailable")
        url = client.async_authorize_url(
            metadata,
            redirect_uri=self._redirect_uri,
            state=state,
            nonce=self._nonce,
            code_verifier=self._code_verifier,
            scopes=list(protocol.scopes),
        )
        return self.async_external_step(step_id="authorize", url=url)

    async def async_step_authorize(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Record the redirect result for the finish step."""
        if user_input is not None:
            self._code = user_input.get("code")
            self._error = user_input.get("error")
        return self.async_external_step_done(next_step_id="finish")

    async def async_step_finish(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Exchange the authorization code and sign the user in."""
        if self._error is not None:
            _LOGGER.debug("Identity provider returned error %s", self._error)
            return self.async_abort(reason="authorize_rejected")
        if self._code is None or self._redirect_uri is None:
            return self.async_abort(reason="authorize_failed")

        provider = self._auth_provider
        client = self._client
        protocol = self._protocol
        generation = self._generation
        if (
            client is None
            or protocol is None
            or generation is None
            or not provider.active
            or provider.generation != generation
        ):
            return self.async_abort(reason="configuration_changed")

        try:
            tokens = await client.async_exchange_code(
                code=self._code,
                redirect_uri=self._redirect_uri,
                code_verifier=self._code_verifier,
            )
        except OidcError as err:
            _LOGGER.error("Could not exchange the authorization code: %s", err)
            return self.async_abort(reason="token_request_failed")

        try:
            if tokens.id_token is None:
                _LOGGER.error("Identity provider did not return an ID token")
                return self.async_abort(reason="missing_id_token")
            try:
                claims = await client.async_verify_id_token(
                    tokens.id_token,
                    nonce=self._nonce,
                    access_token=tokens.access_token,
                )
            except OidcError as err:
                _LOGGER.error("Rejected the ID token: %s", err)
                return self.async_abort(reason="invalid_id_token")
            if not (subject := claims.get("sub")):
                _LOGGER.error("ID token has no subject claim")
                return self.async_abort(reason="missing_subject")

            async with provider.async_config_guard(generation) as config_is_current:
                if not config_is_current:
                    return self.async_abort(reason="configuration_changed")
                account_name = (
                    _claim_as_str(claims.get(protocol.account_name_claim))
                    if protocol.account_name_claim
                    else None
                )
                credentials = await provider.async_get_or_create_credentials(
                    {CONF_ISSUER: client.issuer, CONF_SUBJECT: str(subject)}
                    | ({CONF_ACCOUNT_NAME: account_name} if account_name else {})
                )
                if credentials.is_new and not self.context.get("link_user"):
                    return self.async_abort(reason="user_not_allowed")
            return await self.async_finish_credentials(credentials)
        finally:
            # Nothing is kept that needs the identity provider again later.
            if tokens.refresh_token is not None:
                await client.async_revoke_token(tokens.refresh_token)
