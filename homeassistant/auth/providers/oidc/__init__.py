"""OpenID Connect auth provider.

Sign in is delegated to an external identity provider using the authorization
code flow with PKCE. The provider is configured from the UI.

Because the identity provider is only consulted while signing in, every session
carries a deadline. A background task silently refreshes it against the identity
provider, and drops all Home Assistant refresh tokens as soon as the identity
provider says the session is gone.
"""

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
import logging
import secrets
import time
from typing import Any, cast, override
from weakref import WeakValueDictionary

import jwt
import voluptuous as vol

from homeassistant.const import CONF_ID
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.network import NoURLAvailableError, get_url

from ... import InvalidAuthError
from ...const import GROUP_ID_ADMIN, GROUP_ID_USER
from ...models import (
    TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    RefreshToken,
    UserMeta,
)
from .. import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow
from .client import (
    OidcClient,
    OidcError,
    OidcInvalidGrantError,
    OidcTransientError,
    TokenResponse,
    generate_code_verifier,
)
from .const import (
    AUTH_CALLBACK_PATH,
    CONF_ISSUER,
    CONF_SUBJECT,
    LOGIN_STATE_EXPIRATION,
    PROVIDER_TYPE,
    REVALIDATE_CHECK_INTERVAL,
)
from .store import OidcConfig, OidcSession, OidcStore

_LOGGER = logging.getLogger(__name__)

__all__ = ["OidcAuthProvider", "OidcConfig", "async_get_provider"]


def _disallow_id(conf: dict[str, Any]) -> dict[str, Any]:
    """Disallow ID in config."""
    if CONF_ID in conf:
        raise vol.Invalid("ID is not allowed for the oidc auth provider.")

    return conf


CONFIG_SCHEMA = vol.All(AUTH_PROVIDER_SCHEMA, _disallow_id)


@callback
def async_get_provider(hass: HomeAssistant) -> OidcAuthProvider:
    """Get the provider."""
    for prv in hass.auth.auth_providers:
        if prv.type == PROVIDER_TYPE:
            return cast(OidcAuthProvider, prv)

    raise RuntimeError("Provider not found")


@AUTH_PROVIDERS.register(PROVIDER_TYPE)
class OidcAuthProvider(AuthProvider):
    """Authenticate against an OpenID Connect identity provider."""

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the provider."""
        super().__init__(*args, **kwargs)
        self.data: OidcStore | None = None
        self._client: OidcClient | None = None
        self._init_lock = asyncio.Lock()
        self._config_lock = asyncio.Lock()
        self._revalidate_lock = asyncio.Lock()
        self._pending_credentials: WeakValueDictionary[tuple[str, str], Credentials] = (
            WeakValueDictionary()
        )
        # Regenerated on restart, which only invalidates in flight logins.
        self._state_secret = secrets.token_hex(32)

    @property
    @override
    def support_mfa(self) -> bool:
        """Return that multi-factor auth is owned by the identity provider."""
        return False

    @override
    async def async_initialize(self) -> None:
        """Load the stored data and start revalidating sessions."""
        async with self._init_lock:
            if self.data is not None:
                return

            data = OidcStore(self.hass)
            await data.async_load()
            credential_subjects = {
                credentials.id: credentials.data.get(CONF_SUBJECT)
                for credentials in await self.async_credentials()
            }
            for credential_id, session in list(data.sessions.items()):
                if credential_subjects.get(credential_id) != session.subject:
                    data.async_remove_session(credential_id)
            self.data = data

        async_track_time_interval(
            self.hass,
            self._async_revalidate_sessions,
            REVALIDATE_CHECK_INTERVAL,
            name="OIDC session revalidation",
            cancel_on_shutdown=True,
        )

    async def _async_get_data(self) -> OidcStore:
        """Return the data store, loading it if needed."""
        if self.data is None:
            await self.async_initialize()
            assert self.data is not None

        return self.data

    @property
    def is_configured(self) -> bool:
        """Return if an administrator has configured the provider."""
        return self.data is not None and self.data.config is not None

    @property
    @override
    def name(self) -> str:
        """Return the name the login screen offers this provider under."""
        if self.is_configured and (name := self.oidc_config.name):
            return name
        return super().name

    @property
    def oidc_config(self) -> OidcConfig:
        """Return the settings, which every login and session implies exist."""
        if self.data is None or self.data.config is None:
            raise OidcError("The OIDC auth provider is not configured")
        return self.data.config

    async def async_set_config(self, config: OidcConfig | None) -> None:
        """Replace the configuration."""
        data = await self._async_get_data()
        old_client: OidcClient | None = None
        refresh_tokens: list[str] = []

        async with self._config_lock:
            if data.config == config:
                return

            async with self._revalidate_lock:
                old_client = self.async_client() if data.config is not None else None
                refresh_tokens = [
                    session.refresh_token
                    for session in data.sessions.values()
                    if session.refresh_token is not None
                ]
                await self._async_end_sessions(list(data.sessions.values()))
                data.async_set_config(config)
                self._client = None
                self._pending_credentials.clear()

        if old_client is not None:
            await asyncio.gather(
                *(old_client.async_revoke_token(token) for token in refresh_tokens)
            )

    @asynccontextmanager
    async def async_config_guard(self, config: OidcConfig) -> AsyncIterator[bool]:
        """Guard side effects against concurrent provider reconfiguration."""
        async with self._config_lock:
            yield self.is_configured and self.oidc_config == config

    @callback
    def async_client(self) -> OidcClient:
        """Return a client for the configured identity provider."""
        config = self.oidc_config

        if self._client is None:
            self._client = OidcClient(
                self.hass,
                issuer=config.issuer,
                client_id=config.client_id,
                client_secret=config.client_secret,
            )

        return self._client

    @callback
    def async_redirect_uri(self) -> str:
        """Return the redirect URI to use for the current request."""
        return f"{get_url(self.hass, require_current_request=True)}{AUTH_CALLBACK_PATH}"

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
        identity = (issuer, subject)

        for credentials in await self.async_credentials():
            if (
                credentials.data.get(CONF_ISSUER) == issuer
                and credentials.data.get(CONF_SUBJECT) == subject
            ):
                self._pending_credentials.pop(identity, None)
                return credentials

        if (pending := self._pending_credentials.get(identity)) is None:
            pending = self.async_create_credentials(
                {CONF_ISSUER: issuer, CONF_SUBJECT: subject}
            )
            self._pending_credentials[identity] = pending
        return pending

    @override
    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return the metadata for a user we are about to create."""
        data = await self._async_get_data()
        session = data.sessions.get(credentials.id)
        if session is None:
            raise InvalidAuthError("Sign in with the identity provider again")

        name = session.display_name or session.username

        return UserMeta(
            name=name or credentials.data.get(CONF_SUBJECT),
            is_active=True,
            # A UserMeta without a group would make the new user an owner.
            group=GROUP_ID_ADMIN if session.is_admin else GROUP_ID_USER,
            local_only=False,
        )

    async def async_will_remove_credentials(self, credentials: Credentials) -> None:
        """Drop the identity provider session when the credentials are removed."""
        await self._async_remove_credentials_session(credentials)

    @override
    async def async_auth_code_expired(self, credentials: Credentials) -> None:
        """Drop an unlinked identity provider session when its code expires."""
        if credentials.is_new:
            await self._async_remove_credentials_session(credentials)

    async def _async_remove_credentials_session(self, credentials: Credentials) -> None:
        """Drop and revoke the session for a credential."""
        async with self._config_lock, self._revalidate_lock:
            data = await self._async_get_data()
            if (session := data.sessions.get(credentials.id)) is None:
                return
            client = self.async_client() if self.is_configured else None
            await self._async_end_sessions([session])

        if session.refresh_token and client is not None:
            self.hass.async_create_task(
                client.async_revoke_token(session.refresh_token),
                "Revoke removed OIDC session",
            )

    async def async_sync_admin(
        self, credentials: Credentials, claims: Mapping[str, Any]
    ) -> None:
        """Line the account up with the group memberships of the identity."""
        if credentials.is_new or self.data is None:
            return
        user = await self.hass.auth.async_get_user_by_credentials(credentials)
        # Demoting the owner could leave the instance without an administrator.
        if user is None or user.is_owner:
            return

        grants_admin = self.oidc_config.grants_admin(claims)
        session = self.data.sessions.get(credentials.id)
        granted_by_provider = session is not None and session.is_admin
        group_ids = {group.id for group in user.groups}
        is_admin = GROUP_ID_ADMIN in group_ids

        if grants_admin and not is_admin:
            group_ids.add(GROUP_ID_ADMIN)
        elif is_admin and not grants_admin and granted_by_provider:
            group_ids.discard(GROUP_ID_ADMIN)
            # Every user needs a group, and permissions come from the groups.
            group_ids = group_ids or {GROUP_ID_USER}
        else:
            return

        await self.hass.auth.async_update_user(user, group_ids=sorted(group_ids))

    @callback
    @override
    def async_validate_refresh_token(
        self, refresh_token: RefreshToken, remote_ip: str | None = None
    ) -> None:
        """Reject a refresh token once the identity provider has to be consulted."""
        if refresh_token.token_type == TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN:
            # Long lived access tokens never expire, so they deliberately opt out
            # of revalidation and have to be revoked by hand.
            return

        if (credential := refresh_token.credential) is None:
            return
        if not self.is_configured:
            raise InvalidAuthError("Sign in with the identity provider again")

        assert self.data is not None
        session = self.data.sessions.get(credential.id)
        if session is None:
            raise InvalidAuthError("Sign in with the identity provider again")

        if time.time() >= session.revalidate_after:
            raise InvalidAuthError(
                "The identity provider has to confirm this session again"
            )

    @callback
    def async_encode_state(self, flow_id: str) -> str:
        """Return a signed state parameter that names a login flow."""
        return jwt.encode(
            {"flow_id": flow_id, "exp": int(time.time()) + LOGIN_STATE_EXPIRATION},
            self._state_secret,
            algorithm="HS256",
        )

    @callback
    def async_decode_state(self, state: str) -> str | None:
        """Return the login flow a state parameter belongs to."""
        try:
            claims = jwt.decode(
                state,
                self._state_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "flow_id"]},
            )
        except jwt.InvalidTokenError:
            return None

        flow_id = claims.get("flow_id")
        return flow_id if isinstance(flow_id, str) else None

    async def async_record_session(
        self,
        *,
        credential_id: str,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
    ) -> str | None:
        """Store the identity provider session backing a credential."""
        async with self._revalidate_lock:
            return await self._async_record_session(
                credential_id=credential_id, claims=claims, tokens=tokens
            )

    async def _async_record_session(
        self,
        *,
        credential_id: str,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
    ) -> str | None:
        """Store a session while the caller holds the revalidation lock."""
        config = self.oidc_config
        data = await self._async_get_data()
        previous_refresh_token = (
            previous.refresh_token
            if (previous := data.sessions.get(credential_id)) is not None
            else None
        )

        session = OidcSession(
            credential_id=credential_id,
            subject=str(claims["sub"]),
            refresh_token=tokens.refresh_token,
            username=config.username_from(claims),
            display_name=config.display_name_from(claims),
            is_admin=config.grants_admin(claims),
        )
        session.mark_validated(config.revalidate_interval)
        data.async_set_session(session)
        return (
            previous_refresh_token
            if previous_refresh_token != tokens.refresh_token
            else None
        )

    async def async_complete_login(
        self,
        credentials: Credentials,
        claims: Mapping[str, Any],
        tokens: TokenResponse,
    ) -> str | None:
        """Apply identity claims and commit a session atomically."""
        async with self._revalidate_lock:
            if (
                not credentials.is_new
                and await self.hass.auth.async_get_user_by_credentials(credentials)
                is None
            ):
                raise InvalidAuthError("OIDC credentials were removed")
            await self.async_sync_admin(credentials, claims)
            return await self._async_record_session(
                credential_id=credentials.id, claims=claims, tokens=tokens
            )

    async def _async_revalidate_sessions(self, now: datetime) -> None:
        """Check every session that is due against the identity provider."""
        if not self.is_configured or self.data is None:
            return

        # A slow identity provider can make a pass outlast the interval, and
        # refreshing the same session twice would burn a rotating refresh token.
        if self._revalidate_lock.locked():
            _LOGGER.debug("Previous revalidation pass is still running")
            return

        async with self._revalidate_lock:
            # One snapshot for the whole pass, so a reconfiguration midway cannot
            # apply the old settings to some sessions and the new ones to others.
            data = self.data
            config = self.oidc_config
            timestamp = now.timestamp()
            for session in list(data.sessions.values()):
                if timestamp < session.refresh_after:
                    continue
                await self._async_revalidate_session(data, config, session)

    async def _async_revalidate_session(
        self, data: OidcStore, config: OidcConfig, session: OidcSession
    ) -> None:
        """Ask the identity provider whether a session is still valid."""
        if session.refresh_token is None:
            if time.time() >= session.revalidate_after:
                await self._async_end_session(session)
            return

        try:
            client = self.async_client()
            tokens = await client.async_refresh_token(session.refresh_token)
            if tokens.refresh_token:
                session.refresh_token = tokens.refresh_token
                data.async_set_session(session)
            if tokens.id_token is not None:
                claims = await client.async_verify_id_token(
                    tokens.id_token, access_token=tokens.access_token
                )
                if claims["sub"] != session.subject:
                    _LOGGER.warning(
                        "Refreshed ID token describes a different subject,"
                        " signing out the OIDC session"
                    )
                    await self._async_end_session(session)
                    return
        except OidcInvalidGrantError:
            _LOGGER.info("Identity provider revoked an OIDC session, signing it out")
            await self._async_end_session(session)
            return
        except OidcTransientError as err:
            _LOGGER.debug("Could not revalidate OIDC session yet: %s", err)
            return
        except OidcError as err:
            _LOGGER.warning("Error revalidating OIDC session: %s", err)
            return

        # Only the token and the deadlines move; the identity attributes are read
        # once, while the Home Assistant user is created.
        session.mark_validated(config.revalidate_interval)
        data.async_set_session(session)

    async def _async_end_session(self, session: OidcSession) -> None:
        """Drop a session and every Home Assistant token that depends on it."""
        await self._async_end_sessions([session])

    async def _async_end_sessions(self, sessions: list[OidcSession]) -> None:
        """Drop sessions and every Home Assistant token that depends on them."""
        data = await self._async_get_data()
        credential_ids = {session.credential_id for session in sessions}
        admin_credential_ids = {
            session.credential_id for session in sessions if session.is_admin
        }
        for credential_id in credential_ids:
            data.async_remove_session(credential_id)

        for user in await self.store.async_get_users():
            user_credential_ids = {credentials.id for credentials in user.credentials}
            for refresh_token in list(user.refresh_tokens.values()):
                if (
                    refresh_token.credential is not None
                    and refresh_token.credential.id in credential_ids
                ):
                    self.hass.auth.async_remove_refresh_token(refresh_token)

            if (
                user.is_owner
                or not user_credential_ids & admin_credential_ids
                or any(
                    session.is_admin
                    for credential_id in user_credential_ids
                    if (session := data.sessions.get(credential_id)) is not None
                )
            ):
                continue

            group_ids = {group.id for group in user.groups}
            if GROUP_ID_ADMIN not in group_ids:
                continue
            group_ids.remove(GROUP_ID_ADMIN)
            await self.hass.auth.async_update_user(
                user, group_ids=sorted(group_ids or {GROUP_ID_USER})
            )


class OidcLoginFlow(LoginFlow[OidcAuthProvider]):
    """Handler for the OpenID Connect login flow."""

    def __init__(self, auth_provider: OidcAuthProvider) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._code_verifier = generate_code_verifier()
        self._nonce = secrets.token_urlsafe(32)
        self._redirect_uri: str | None = None
        self._code: str | None = None
        self._error: str | None = None
        self._config: OidcConfig | None = None
        self._client: OidcClient | None = None

    @override
    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Send the user to the identity provider."""
        provider = self._auth_provider
        if not provider.is_configured:
            return self.async_abort(reason="not_configured")

        config = provider.oidc_config

        try:
            self._redirect_uri = provider.async_redirect_uri()
        except NoURLAvailableError:
            return self.async_abort(reason="no_url_available")

        client = provider.async_client()
        try:
            metadata = await client.async_metadata()
        except OidcError as err:
            _LOGGER.error("Could not reach the identity provider: %s", err)
            return self.async_abort(reason="provider_unavailable")

        self._config = config
        self._client = client
        return self.async_external_step(
            step_id="authorize",
            url=client.async_authorize_url(
                metadata,
                redirect_uri=self._redirect_uri,
                state=provider.async_encode_state(self.flow_id),
                nonce=self._nonce,
                code_verifier=self._code_verifier,
                scopes=config.scopes,
            ),
        )

    async def async_step_authorize(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Collect the result of the redirect.

        An external step may only move to another external step or to done, so
        failures are recorded and reported by the next step.
        """
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
        config = self._config
        client = self._client
        if (
            config is None
            or client is None
            or not provider.is_configured
            or provider.oidc_config != config
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

        session_committed = False
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

            async with provider.async_config_guard(config) as config_is_current:
                if not config_is_current:
                    return self.async_abort(reason="configuration_changed")

                credentials = await provider.async_get_or_create_credentials(
                    {CONF_ISSUER: str(claims["iss"]), CONF_SUBJECT: str(subject)}
                )

                # /auth/link_user authorizes attaching a new identity.
                if (
                    credentials.is_new
                    and not self.context.get("link_user")
                    and not config.allow_auto_create
                ):
                    return self.async_abort(reason="user_not_allowed")

                if credentials.is_new and config.needs_userinfo(claims):
                    try:
                        claims = await client.async_merge_userinfo(
                            claims, tokens.access_token
                        )
                    except OidcError as err:
                        _LOGGER.error("Could not read the userinfo endpoint: %s", err)
                        return self.async_abort(reason="userinfo_failed")

                try:
                    replaced_refresh_token = await provider.async_complete_login(
                        credentials, claims, tokens
                    )
                except InvalidAuthError:
                    return self.async_abort(reason="authorize_failed")
                session_committed = True

            if replaced_refresh_token is not None:
                await client.async_revoke_token(replaced_refresh_token)
            return await self.async_finish(credentials)
        finally:
            if not session_committed and tokens.refresh_token is not None:
                await client.async_revoke_token(tokens.refresh_token)
