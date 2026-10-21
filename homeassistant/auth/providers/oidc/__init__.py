"""OpenID Connect identity provider engine."""

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
import logging
import secrets
import time
from typing import Any, cast, override
from weakref import WeakValueDictionary

import probatio

from homeassistant.const import CONF_ID
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.network import (
    NoURLAvailableError,
    get_url,
    is_internal_request,
)
from homeassistant.helpers.oauth2 import generate_code_verifier

from ... import InvalidAuthError
from ...const import GROUP_ID_ADMIN, GROUP_ID_USER, LOGIN_CALLBACK_PATH
from ...models import (
    TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    RefreshToken,
    User,
    UserMeta,
)
from .. import (
    AUTH_PROVIDER_SCHEMA,
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
    MfaLoginFlow,
)
from .client import (
    IdentityClient,
    OAuth2IdentityClient,
    OidcClient,
    OidcError,
    OidcInsecureTransportError,
    OidcInvalidGrantError,
    OidcTransientError,
    ProviderMetadata,
    TokenResponse,
    async_discover,
)
from .const import (
    CONF_ISSUER,
    CONF_SUBJECT,
    DEFAULT_REVALIDATE_INTERVAL,
    GROUPS_CLAIM,
    PROVIDER_TYPE,
    REVALIDATE_CHECK_INTERVAL,
    UNCLAIMED_SESSION_TIMEOUT,
)
from .spec import (
    AccountPolicy,
    ClaimRule,
    Equals,
    IdentityProvider,
    IdentityProviderError,
    NotEquals,
    OpenIDConnect,
    ProtocolSpec,
    trust_key,
    validate_identity_provider,
)
from .store import IdentityProviderRecord, OidcSession, OidcStore

_LOGGER = logging.getLogger(__name__)

CONF_ACCOUNT_NAME = "account_name"

__all__ = [
    "AccountPolicy",
    "ClaimRule",
    "Equals",
    "IdentityProvider",
    "IdentityProviderError",
    "NotEquals",
    "OidcAuthProvider",
    "OidcIdentityProvider",
    "OpenIDConnect",
    "ProtocolSpec",
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


def _claim_as_list(value: Any) -> list[str]:
    """Return a claim that may be a list or a space separated string."""
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _username_from(spec: OpenIDConnect, claims: Mapping[str, Any]) -> str | None:
    """Return the username a set of claims maps to."""
    return _claim_as_str(claims.get(spec.username_claim))


def _display_name_from(spec: OpenIDConnect, claims: Mapping[str, Any]) -> str | None:
    """Return the display name a set of claims maps to."""
    return _claim_as_str(claims.get(spec.display_name_claim))


def _grants_admin(spec: OpenIDConnect, claims: Mapping[str, Any]) -> bool:
    """Return if the group memberships grant administrator access."""
    return bool(spec.admin_group) and spec.admin_group in _claim_as_list(
        claims.get(GROUPS_CLAIM)
    )


def _needs_userinfo(spec: OpenIDConnect, claims: Mapping[str, Any]) -> bool:
    """Return if a claim needed to create an account is missing."""
    return any(
        claim not in claims for claim in (spec.username_claim, spec.display_name_claim)
    )


def _claim_matches(rule: ClaimRule, value: Any) -> bool:
    """Return if a claim value satisfies a required claim rule."""
    if isinstance(rule, Equals):
        return bool(value == rule.value)
    return bool(value != rule.value)


def _required_claims_match(protocol: OpenIDConnect, claims: Mapping[str, Any]) -> bool:
    """Return if all required claims are satisfied."""
    return all(
        claim in claims and _claim_matches(rule, claims[claim])
        for claim, rule in protocol.required_claims.items()
    )


def _build_client(hass: HomeAssistant, spec: IdentityProvider) -> IdentityClient:
    """Return the protocol client for a validated spec."""
    try:
        return spec.protocol.create_client(hass, spec)
    except (ValueError, OidcError) as err:
        raise IdentityProviderError("invalid_spec", str(err)) from err


def _revoke_refresh_tokens(
    hass: HomeAssistant, client: IdentityClient | None, sessions: list[OidcSession]
) -> None:
    """Revoke the external refresh tokens of ended sessions in the background."""
    if client is None:
        return
    for session in sessions:
        if session.refresh_token is not None:
            hass.async_create_task(
                client.async_revoke_token(session.refresh_token),
                "Revoke ended OIDC session",
            )


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
    hass: HomeAssistant, discovery_url: str, *, allow_insecure_transport: bool = False
) -> ProviderMetadata:
    """Fetch and validate an OpenID Connect discovery document."""
    with _discovery_errors():
        return await async_discover(
            hass, discovery_url, allow_insecure_transport=allow_insecure_transport
        )


async def async_validate_identity_provider(
    hass: HomeAssistant, spec: IdentityProvider
) -> IdentityProvider:
    """Validate a spec the way registration does, and reach its discovery document."""
    validated = validate_identity_provider(spec)
    client = _build_client(hass, validated)
    if isinstance(client, OidcClient):
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
        self._revalidate_lock = asyncio.Lock()
        self._children: dict[str, OidcIdentityProvider] = {}
        self._unsub_revalidate: CALLBACK_TYPE | None = None

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
        """Load the stored registry and start deadline enforcement."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = OidcStore(self.hass)
            await data.async_load()
            credential_subjects = {
                credentials.id: credentials.data.get(CONF_SUBJECT)
                for user in await self.store.async_get_users()
                for credentials in user.credentials
                if credentials.auth_provider_type == PROVIDER_TYPE
            }
            for credential_id, session in list(data.sessions.items()):
                if credential_subjects.get(credential_id) != session.subject:
                    data.async_remove_session(credential_id)
            self.data = data
            for record in data.records.values():
                self._async_child_for_record(record)

        self.async_schedule_revalidation()

    @property
    def config_lock(self) -> asyncio.Lock:
        """Return the provider configuration lock."""
        return self._config_lock

    @property
    def revalidate_lock(self) -> asyncio.Lock:
        """Return the session revalidation lock."""
        return self._revalidate_lock

    async def async_get_data(self) -> OidcStore:
        """Return the data store, loading it if needed."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None
        return self.data

    @callback
    def async_schedule_revalidation(self) -> None:
        """Run the revalidation timer only while sessions need deadlines."""
        should_run = bool(self.data and self.data.sessions)
        if should_run and self._unsub_revalidate is None:
            self._unsub_revalidate = async_track_time_interval(
                self.hass,
                self._async_revalidate_sessions,
                REVALIDATE_CHECK_INTERVAL,
                name="OIDC session revalidation",
                cancel_on_shutdown=True,
            )
        elif not should_run and self._unsub_revalidate is not None:
            self._unsub_revalidate()
            self._unsub_revalidate = None

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
            record = IdentityProviderRecord(
                idp_id=idp_id, domain=domain, accounts=validated.accounts, trust_key=key
            )
            data.async_set_record(record)
            child = self._async_child_for_record(record)
            child.async_activate(
                title=title, spec=validated, record=record, client=client
            )

        self.async_schedule_revalidation()

    @callback
    def async_suspend_identity_provider(self, idp_id: str) -> None:
        """Suspend an unloaded or failed identity provider entry."""
        if child := self._children.get(idp_id):
            child.async_suspend()
        self.async_schedule_revalidation()

    async def async_end_identity_provider_sessions(self, idp_id: str) -> None:
        """End Home Assistant sessions derived from an identity provider."""
        child = self._children.get(idp_id)
        await self._async_end_identity_provider_sessions(
            idp_id, child.revocation_client if child else None
        )

    async def _async_end_identity_provider_sessions(
        self, idp_id: str, client: IdentityClient | None
    ) -> None:
        """End sessions of an identity provider, revoking with the given client."""
        data = await self.async_get_data()
        async with self._revalidate_lock:
            sessions = [
                session
                for session in data.sessions.values()
                if session.idp_id == idp_id
            ]
            await self.async_end_sessions(sessions)
            if child := self._children.get(idp_id):
                for credentials in await child.async_credentials():
                    await self.hass.auth.async_remove_refresh_tokens_for_credentials(
                        credentials
                    )
        _revoke_refresh_tokens(self.hass, client, sessions)
        self.async_schedule_revalidation()

    async def async_remove_identity_provider(self, idp_id: str) -> list[User]:
        """Remove an identity provider and its credentials."""
        data = await self.async_get_data()
        removed_users: list[User] = []
        async with self._config_lock:
            # Suspending first makes logins still in flight abort.
            child = self._children.get(idp_id)
            client = child.revocation_client if child else None
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

            await self._async_end_identity_provider_sessions(idp_id, client)
            for owned in credentials_by_user.values():
                for credential in owned:
                    await self.hass.auth.async_remove_credentials(credential)

        data.async_remove_record(idp_id)
        self._children.pop(idp_id, None)
        self.async_schedule_revalidation()
        return removed_users

    async def _async_revalidate_sessions(self, now: datetime) -> None:
        """Enforce deadlines and refresh active OIDC sessions."""
        if self.data is None:
            return
        await self._async_expire_sessions()
        for idp in list(self._children.values()):
            await idp.async_drop_unclaimed_sessions()
        if self._revalidate_lock.locked():
            _LOGGER.debug("Previous revalidation pass is still running")
            return

        async with self._revalidate_lock:
            timestamp = now.timestamp()
            expired: list[OidcSession] = []
            for session in list(self.data.sessions.values()):
                if timestamp < session.refresh_after:
                    continue
                child = self._children.get(session.idp_id)
                if child is None or not child.active:
                    if timestamp >= session.revalidate_after:
                        expired.append(session)
                    continue
                if await child.async_revalidate_session(self.data, session):
                    expired.append(session)

            if expired:
                await self.async_end_sessions(expired)
        self.async_schedule_revalidation()

    async def _async_expire_sessions(self) -> None:
        """End every session whose deadline has passed, without network I/O."""
        assert self.data is not None
        now = time.time()
        expired = [
            session
            for session in self.data.sessions.values()
            if now >= session.revalidate_after
        ]
        if expired:
            _LOGGER.info(
                "Ending %s OIDC session(s) that reached their deadline", len(expired)
            )
            await self.async_end_sessions(expired)

    async def async_end_sessions(self, sessions: list[OidcSession]) -> None:
        """Drop sessions and every Home Assistant token that depends on them."""
        data = await self.async_get_data()
        credential_ids = {session.credential_id for session in sessions}
        admin_credential_ids = {
            session.credential_id for session in sessions if session.is_admin
        }
        for credential_id in credential_ids:
            data.async_remove_session(credential_id)

        for child in self._children.values():
            for credentials in await child.async_credentials():
                if credentials.id in credential_ids:
                    await self.hass.auth.async_remove_refresh_tokens_for_credentials(
                        credentials
                    )

        for user in await self.store.async_get_users():
            user_credential_ids = {credentials.id for credentials in user.credentials}
            group_ids = {group.id for group in user.groups}
            if (
                user.is_owner
                or GROUP_ID_ADMIN not in group_ids
                or not user_credential_ids & admin_credential_ids
                or any(
                    session.is_admin
                    for credential_id in user_credential_ids
                    if (session := data.sessions.get(credential_id)) is not None
                )
            ):
                continue

            group_ids.remove(GROUP_ID_ADMIN)
            await self.hass.auth.async_update_user(
                user, group_ids=sorted(group_ids or {GROUP_ID_USER})
            )


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
        self._client: IdentityClient | None = None
        self._revocation_client: IdentityClient | None = None
        self._generation = 0
        self._pending_credentials: WeakValueDictionary[tuple[str, str], Credentials] = (
            WeakValueDictionary()
        )
        # New credentials holding a session, with the deadline for claiming them.
        self._unclaimed: dict[str, tuple[Credentials, float]] = {}

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
    def protocol(self) -> ProtocolSpec | None:
        """Return the runtime protocol spec."""
        return self._spec.protocol if self._spec is not None else None

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
        client: IdentityClient,
    ) -> None:
        """Activate the child with a runtime spec."""
        self.record = record
        self._title = title
        self._spec = spec
        self._client = client
        self._revocation_client = client
        self._generation += 1
        self._pending_credentials.clear()

    @callback
    def async_suspend(self) -> None:
        """Make the child dormant while keeping its client for token revocation."""
        self._spec = None
        self._client = None
        self._generation += 1
        self._pending_credentials.clear()

    @property
    def revocation_client(self) -> IdentityClient | None:
        """Return the last active client, if available, for token revocation."""
        return self._revocation_client

    @callback
    @override
    def async_can_start_login(self, context: AuthFlowContext) -> bool:
        """Return if this identity provider is active."""
        return self.active

    @callback
    @override
    def async_can_login_with_credentials(self, credentials: Credentials) -> bool:
        """Return if these credentials are usable as a fallback login."""
        if not self.active:
            return False
        issuer = credentials.data.get(CONF_ISSUER)
        return isinstance(issuer, str) and self.async_client().accepts_issuer(issuer)

    @callback
    def async_redirect_uri(self) -> str:
        """Return the redirect URI, refusing plain HTTP reachable from outside."""
        url = get_url(self.hass, require_current_request=True)
        if (
            not url.startswith("https://")
            and not self.spec.allow_insecure_transport
            and not is_internal_request(self.hass)
        ):
            raise OidcInsecureTransportError(
                f"Signing in through {url} would expose the tokens, use HTTPS"
            )
        return f"{url}{LOGIN_CALLBACK_PATH}"

    @callback
    def async_client(self) -> IdentityClient:
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
        """Return metadata for a user we are about to create."""
        if self.record.accounts is AccountPolicy.LINK:
            raise InvalidAuthError("The identity provider may only link users")

        data = await self.root.async_get_data()
        session = data.sessions.get(credentials.id)
        if session is None:
            raise InvalidAuthError("Sign in with the identity provider again")

        name = session.display_name or session.username
        return UserMeta(
            name=name or credentials.data.get(CONF_SUBJECT),
            is_active=True,
            group=GROUP_ID_ADMIN if session.is_admin else GROUP_ID_USER,
            local_only=False,
        )

    @override
    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """Drop provider state and tokens when credentials are removed."""
        await self._async_remove_credentials_session(credentials)
        await self.hass.auth.async_remove_refresh_tokens_for_credentials(credentials)

    async def _async_remove_credentials_session(self, credentials: Credentials) -> None:
        """Drop and revoke the session for a credential."""
        async with self.root.config_lock, self.root.revalidate_lock:
            data = await self.root.async_get_data()
            if (session := data.sessions.get(credentials.id)) is None:
                return
            client = self._revocation_client
            await self.root.async_end_sessions([session])

        if session.refresh_token and client is not None:
            self.hass.async_create_task(
                client.async_revoke_token(session.refresh_token),
                "Revoke removed OIDC session",
            )

    @callback
    @override
    def async_validate_refresh_token(
        self, refresh_token: RefreshToken, remote_ip: str | None = None
    ) -> None:
        """Reject a refresh token once the identity provider must be consulted."""
        if refresh_token.token_type == TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN:
            # Long lived tokens opt out of revalidation and are revoked by hand.
            return
        # A code minted before suspension must not start a fresh HA session.
        if refresh_token.last_used_at is None and not self.active:
            raise InvalidAuthError("Sign in with the identity provider again")
        if (
            self.record.accounts is AccountPolicy.LINK
            or (credential := refresh_token.credential) is None
        ):
            return

        data = self.root.data
        if (
            data is None
            or (session := data.sessions.get(credential.id)) is None
            or session.idp_id != self.id
        ):
            raise InvalidAuthError("Sign in with the identity provider again")
        if time.time() >= session.revalidate_after:
            raise InvalidAuthError(
                "The identity provider has to confirm this session again"
            )

    async def async_record_session(
        self,
        *,
        credential_id: str,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
        profile_claims: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Store the identity provider session backing a credential."""
        async with self.root.revalidate_lock:
            return await self._async_record_session(
                credential_id=credential_id,
                claims=claims,
                tokens=tokens,
                profile_claims=profile_claims,
            )

    async def _async_record_session(
        self,
        *,
        credential_id: str,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
        profile_claims: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Store a session while the caller holds the revalidation lock."""
        spec = self.spec
        protocol = cast(OpenIDConnect, spec.protocol)
        data = await self.root.async_get_data()
        if profile_claims is None:
            profile_claims = claims
        previous = data.sessions.get(credential_id)
        replaced = previous.refresh_token if previous is not None else None
        interval = spec.revalidate_interval or timedelta(
            seconds=DEFAULT_REVALIDATE_INTERVAL
        )

        session = OidcSession(
            credential_id=credential_id,
            idp_id=cast(str, self.id),
            subject=str(claims["sub"]),
            refresh_token=tokens.refresh_token,
            username=_username_from(protocol, profile_claims),
            display_name=_display_name_from(protocol, profile_claims),
            is_admin=_grants_admin(protocol, claims),
        )
        session.mark_validated(interval.total_seconds())
        data.async_set_session(session)
        self.root.async_schedule_revalidation()
        return replaced if replaced != tokens.refresh_token else None

    async def async_complete_login(
        self,
        credentials: Credentials,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
        *,
        profile_claims: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Apply identity claims and commit a session atomically."""
        async with self.root.revalidate_lock:
            if not credentials.is_new:
                user = await self.hass.auth.async_get_user_by_credentials(credentials)
                if user is None:
                    raise InvalidAuthError("OIDC credentials were removed")
                session = (await self.root.async_get_data()).sessions.get(
                    credentials.id
                )
                await self._async_apply_admin_grant(
                    user,
                    granted_by_provider=session is not None and session.is_admin,
                    grants_admin=_grants_admin(
                        cast(OpenIDConnect, self.spec.protocol), claims
                    ),
                )
            replaced = await self._async_record_session(
                credential_id=credentials.id,
                claims=claims,
                tokens=tokens,
                profile_claims=profile_claims,
            )

        if credentials.is_new:
            self._unclaimed[credentials.id] = (
                credentials,
                time.time() + UNCLAIMED_SESSION_TIMEOUT.total_seconds(),
            )
        return replaced

    async def async_drop_unclaimed_sessions(self) -> None:
        """Drop sessions of logins whose authorization code was never used."""
        now = time.time()
        for credential_id, (credentials, deadline) in list(self._unclaimed.items()):
            if credentials.is_new and now < deadline:
                continue
            del self._unclaimed[credential_id]
            if credentials.is_new:
                await self._async_remove_credentials_session(credentials)

    async def _async_user_for_credential(self, credential_id: str) -> User | None:
        """Return the user a credential belongs to."""
        for user in await self.store.async_get_users():
            if any(credentials.id == credential_id for credentials in user.credentials):
                return user
        return None

    async def _async_apply_admin_grant(
        self,
        user: User | None,
        *,
        granted_by_provider: bool,
        grants_admin: bool,
    ) -> None:
        """Line a user's groups up with what the identity provider grants."""
        if user is None or user.is_owner:
            return

        group_ids = {group.id for group in user.groups}
        is_admin = GROUP_ID_ADMIN in group_ids
        if grants_admin and not is_admin:
            group_ids.add(GROUP_ID_ADMIN)
        elif is_admin and not grants_admin and granted_by_provider:
            group_ids.discard(GROUP_ID_ADMIN)
            group_ids = group_ids or {GROUP_ID_USER}
        else:
            return
        await self.hass.auth.async_update_user(user, group_ids=sorted(group_ids))

    @callback
    def _async_session_is_current(self, data: OidcStore, session: OidcSession) -> bool:
        """Return if the store still holds this exact session object."""
        return data.sessions.get(session.credential_id) is session

    async def async_revalidate_session(
        self, data: OidcStore, session: OidcSession
    ) -> bool:
        """Ask the identity provider about a session; return if it must end."""
        if session.refresh_token is None:
            return time.time() >= session.revalidate_after

        # One snapshot, so a reconfiguration midway cannot mix settings.
        spec = self.spec
        protocol = cast(OpenIDConnect, spec.protocol)
        client = cast(OidcClient, self.async_client())
        try:
            tokens = await client.async_refresh_token(session.refresh_token)
        except OidcInvalidGrantError:
            _LOGGER.info("Identity provider revoked an OIDC session, signing it out")
            return True
        except OidcTransientError as err:
            _LOGGER.debug("Could not revalidate OIDC session yet: %s", err)
            return time.time() >= session.revalidate_after
        except OidcError as err:
            _LOGGER.warning("Error revalidating OIDC session: %s", err)
            return time.time() >= session.revalidate_after

        if not self._async_session_is_current(data, session):
            return False
        if tokens.refresh_token:
            session.refresh_token = tokens.refresh_token
            data.async_set_session(session)

        if tokens.id_token is not None:
            try:
                claims = await client.async_verify_id_token(
                    tokens.id_token, access_token=tokens.access_token
                )
            except OidcTransientError as err:
                _LOGGER.debug("Could not verify the refreshed ID token yet: %s", err)
                return time.time() >= session.revalidate_after
            except OidcError as err:
                _LOGGER.warning("Refreshed ID token rejected: %s", err)
                return time.time() >= session.revalidate_after
            if claims["sub"] != session.subject or not _required_claims_match(
                protocol, claims
            ):
                _LOGGER.warning("Refreshed ID token no longer matches the OIDC session")
                return True
            await self._async_apply_refreshed_groups(data, protocol, session, claims)

        if not self._async_session_is_current(data, session):
            return False
        interval = spec.revalidate_interval or timedelta(
            seconds=DEFAULT_REVALIDATE_INTERVAL
        )
        session.mark_validated(interval.total_seconds())
        data.async_set_session(session)
        return False

    async def _async_apply_refreshed_groups(
        self,
        data: OidcStore,
        protocol: OpenIDConnect,
        session: OidcSession,
        claims: Mapping[str, Any],
    ) -> None:
        """Apply group memberships a refreshed ID token states."""
        if GROUPS_CLAIM not in claims:
            return
        grants_admin = _grants_admin(protocol, claims)
        await self._async_apply_admin_grant(
            await self._async_user_for_credential(session.credential_id),
            granted_by_provider=session.is_admin,
            grants_admin=grants_admin,
        )
        if session.is_admin != grants_admin:
            session.is_admin = grants_admin
            data.async_set_session(session)


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
        self._client: IdentityClient | None = None
        self._protocol: ProtocolSpec | None = None

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
        if isinstance(client, OAuth2IdentityClient):
            url = client.async_authorize_url(
                redirect_uri=self._redirect_uri,
                state=state,
                code_verifier=self._code_verifier,
            )
            return self.async_external_step(step_id="authorize", url=url)

        assert isinstance(client, OidcClient)
        assert isinstance(protocol, OpenIDConnect)
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
        generation = self._generation
        if (
            client is None
            or generation is None
            or not provider.active
            or provider.generation != generation
        ):
            return self.async_abort(reason="configuration_changed")

        if isinstance(client, OAuth2IdentityClient):
            return await self._async_finish_oauth2(client, generation)
        assert isinstance(client, OidcClient)
        assert isinstance(self._protocol, OpenIDConnect)
        return await self._async_finish_oidc(client, self._protocol, generation)

    async def _async_finish_login(self, credentials: Credentials) -> AuthFlowResult:
        """Finish with the resolved credentials, asking linked accounts for MFA."""
        # An account the identity provider created leaves the second factor to it.
        if self._auth_provider.record.accounts is AccountPolicy.PROVISION:
            return await LoginFlow.async_finish(self, credentials)
        return await self.async_finish_credentials(credentials)

    async def _async_finish_oidc(
        self, client: OidcClient, protocol: OpenIDConnect, generation: int
    ) -> AuthFlowResult:
        """Finish an OpenID Connect flow."""
        provider = self._auth_provider
        try:
            tokens = await client.async_exchange_code(
                code=cast(str, self._code),
                redirect_uri=cast(str, self._redirect_uri),
                code_verifier=self._code_verifier,
            )
        except OidcError as err:
            _LOGGER.error("Could not exchange the authorization code: %s", err)
            return self.async_abort(reason="token_request_failed")

        keep_refresh_token = False
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
            if not _required_claims_match(protocol, claims):
                return self.async_abort(reason="claim_rejected")

            async with provider.async_config_guard(generation) as config_is_current:
                if not config_is_current:
                    return self.async_abort(reason="configuration_changed")
                issuer = client.canonical_issuer(claims)
                account_name = (
                    _claim_as_str(claims.get(protocol.account_name_claim))
                    if protocol.account_name_claim
                    else None
                )
                credentials = await provider.async_get_or_create_credentials(
                    {
                        CONF_ISSUER: issuer,
                        CONF_SUBJECT: str(subject),
                    }
                    | ({CONF_ACCOUNT_NAME: account_name} if account_name else {})
                )
                if (
                    credentials.is_new
                    and not self.context.get("link_user")
                    and provider.record.accounts is AccountPolicy.LINK
                ):
                    return self.async_abort(reason="user_not_allowed")
                profile_claims = claims
                if (
                    provider.record.accounts is AccountPolicy.PROVISION
                    and credentials.is_new
                    and _needs_userinfo(protocol, claims)
                ):
                    try:
                        profile_claims = await client.async_merge_userinfo(
                            claims, tokens.access_token
                        )
                    except OidcError as err:
                        _LOGGER.error("Could not read the userinfo endpoint: %s", err)
                        return self.async_abort(reason="userinfo_failed")
                replaced_refresh_token = None
                if provider.record.accounts is AccountPolicy.PROVISION:
                    try:
                        replaced_refresh_token = await provider.async_complete_login(
                            credentials,
                            claims,
                            tokens,
                            profile_claims=profile_claims,
                        )
                    except InvalidAuthError:
                        return self.async_abort(reason="authorize_failed")
                    keep_refresh_token = True

            if replaced_refresh_token is not None:
                await client.async_revoke_token(replaced_refresh_token)
            return await self._async_finish_login(credentials)
        finally:
            if not keep_refresh_token and tokens.refresh_token is not None:
                await client.async_revoke_token(tokens.refresh_token)

    async def _async_finish_oauth2(
        self, client: OAuth2IdentityClient, generation: int
    ) -> AuthFlowResult:
        """Finish a plain OAuth2 flow, which can only link accounts."""
        provider = self._auth_provider
        try:
            tokens = await client.async_exchange_code(
                code=cast(str, self._code),
                redirect_uri=cast(str, self._redirect_uri),
                code_verifier=self._code_verifier,
            )
            subject, account_name = await client.async_fetch_identity(
                tokens.access_token
            )
        except OidcError as err:
            _LOGGER.error("Could not finish the OAuth2 flow: %s", err)
            return self.async_abort(reason="authorize_failed")

        async with provider.async_config_guard(generation) as config_is_current:
            if not config_is_current:
                return self.async_abort(reason="configuration_changed")
            credentials = await provider.async_get_or_create_credentials(
                {CONF_ISSUER: client.issuer, CONF_SUBJECT: subject}
                | ({CONF_ACCOUNT_NAME: account_name} if account_name else {})
            )
            if credentials.is_new and not self.context.get("link_user"):
                return self.async_abort(reason="user_not_allowed")
        return await self._async_finish_login(credentials)
