---
title: OpenID Connect auth provider
description: Security and design decisions for the Home Assistant OIDC auth provider
---

This document records the design decisions behind this provider and, more
importantly, why they were taken. It exists so the trade-offs do not have to be
rediscovered or relitigated later.

## Scope

- The provider is configured entirely from the UI, through the websocket API in
  `homeassistant/components/config/auth_provider_oidc.py`. There is no YAML
  configuration beyond enabling the provider.
- It is enabled by default in `core_config.py`, but stays hidden from the login
  screen until an administrator has configured an issuer.
- The frontend side of the login flow lives in the frontend repository, as do
  the translated abort reasons. Nothing in this package renders UI.

## Dependencies

### PyJWT and aiohttp only

No new dependency was added. PyJWT is already a core dependency and covers
signature verification, and aiohttp is the HTTP stack the rest of Home Assistant
uses.

Authlib was considered and rejected. Its async client is built on httpx, which
would pull a second HTTP stack into core purely for this provider, and its
`authlib.jose` module is deprecated in favour of `joserfc`.

`jwt.PyJWKClient` must never be used here: it fetches over synchronous urllib and
would block the event loop. The JWKS is fetched with aiohttp and handed to
`jwt.PyJWKSet.from_dict()` instead.

### Why the config entry OAuth2 helpers are not reused

`homeassistant/helpers/config_entry_oauth2_flow.py` looks like a fit but is not
usable for authentication:

1. `async_get_redirect_uri()` returns `https://my.home-assistant.io/redirect/oauth`
   whenever the `my` component is loaded, which is part of `default_config`. That
   would route login authorization codes through a third party. It also hardcodes
   `/auth/external/callback`, which is bound to the config entry flow manager.
2. `LocalOAuth2ImplementationWithPkce` generates one `code_verifier` per instance,
   and its `extra_authorize_data` hooks are instance properties with no request
   context. PKCE has to be per login attempt.
3. `_encode_jwt` signs with a hass-global secret and emits no `exp` claim, so
   states never expire.
4. `_token_request` maps every 4xx to a reauth error by status code and discards
   the `error` field from the body. That loses the `invalid_grant` distinction
   this provider relies on to decide that a session was revoked.
5. Only `client_secret_post` client authentication is supported.
6. Importing it from the auth package pulls in 104 extra modules, including
   `bleak` and `bluetooth_data_tools` by way of `habluetooth`, and the import
   chain reaches back into `homeassistant.auth`.

Extracting the token request into a shared lower-level helper would be a
reasonable follow-up, but belongs in its own pull request.

## Login flow

The authorization code flow with PKCE (`S256`) is used, with or without a client
secret. The browser leaves Home Assistant entirely and comes back to
`/auth/oidc/callback`, which is registered by the `auth` component.

The callback view validates the state, confirms the flow exists, checks the
browser and IP address that started it, and verifies the original relying-client
redirect URI before feeding the code into the flow. It then redirects to
`/auth/authorize?flow_id=...&auth_callback=1`. The frontend restores its own
`client_id`, `redirect_uri` and `state` from storage and posts to the login flow
one final time.

Constraints that shaped this:

- A data entry flow in `EXTERNAL_STEP` may only move to another external step or
  to `EXTERNAL_STEP_DONE`. Aborting from an external step raises `ValueError`,
  so `async_step_authorize` records failures and lets `async_step_finish` report
  them.
- `EXTERNAL_STEP_DONE` needs a second `async_configure` call before the flow
  reaches `CREATE_ENTRY`, which is what the final frontend post provides.

The `state` parameter is a JWT signed with a per-process secret and carries a
five minute expiry. The secret is regenerated on restart, which only invalidates
logins that were already in flight. The `nonce` and the PKCE `code_verifier`
never leave the server.

A signed state only proves that a flow existed, so the flow is also tied to the
browser it started in. Creating a login flow sets a cookie whose name includes
the flow ID. The callback and the final frontend post both require it. Per-flow
names keep simultaneous logins independent, and retaining the cookie through the
final post prevents another browser on the same IP address from completing the
flow. Without that binding, somebody able to deliver their own callback URL to a
victim could sign that victim into an account they never authenticated as. The
cookie is `HttpOnly`, scoped to `/auth`, and `SameSite=Lax` rather than `Strict`,
because the identity provider sends the user back with a cross-site top-level
navigation that `Strict` would strip it from.

The Home Assistant authorization code is also bound to its purpose. A code
issued for `/auth/link_user` cannot be exchanged at `/auth/token`, and trying the
wrong endpoint does not consume it. Unused codes expire after ten minutes. When
the final code for a new identity expires, its unlinked OIDC session and external
refresh token are removed as well.

## Identity and account mapping

The credential key is the verified `iss` and `sub` pair. Per OIDC Core 5.7, the
subject is only unique within an issuer, so binding both means repointing Home
Assistant at a different identity provider cannot hand over existing accounts.
The subject is not configurable: another claim can be signed yet still be
reassignable, which would turn reassignment into account takeover.

Nothing other than issuer and subject is treated as an identifier. An earlier
design allowed matching an existing user by `preferred_username`; it was removed
because OIDC Core 5.7 states that claim is neither unique nor stable, which made
it an account takeover vector.

Automatic account creation is off by default. Because the provisioning check has
to run after the authorization code has already been exchanged, the flow still
issues credentials when the login carries the `link_user` context, so that
`/auth/link_user` can attach the identity to an account that is already signed
in. Without that carve-out no user could ever get in on a fresh install.

## Claims

| Claim | Configurable | Read when |
| --- | --- | --- |
| Subject | No, always `sub` | Every login, ID token only |
| Username | Yes, `username_claim` | Account creation |
| Display name | Yes, `display_name_claim` | Account creation |
| Groups | No, always `groups` | Every login |

The display name is only applied while the account is being built. Renaming a
user in Home Assistant is therefore permanent and is not undone by the next
login.

Nested claim paths are not supported. A claim name is a plain key lookup.

### Userinfo endpoint

The userinfo endpoint is consulted only when an account is about to be created
and the ID token is missing `username_claim` or `display_name_claim`. A returning
user never costs a request, and neither does a provider that puts everything in
the ID token.

OIDC Core 5.3.2 requires that a userinfo response is discarded unless its `sub`
matches the ID token exactly, because a substituted access token would otherwise
import somebody else's claims. That check is enforced before anything is merged,
and a mismatch aborts the login. Since `sub` must always be present in a userinfo
response, a response without one fails the same comparison and is rejected.

Conditional fetching does not weaken that requirement: 5.3.2 constrains how a
response is used, not whether one is requested, so the check holds every time it
applies. Comparison is a plain `!=` on the decoded strings, which is the
code point equality that OIDC Core 14 mandates; Unicode normalization must not be
applied.

Merging is `userinfo | id_token`, so the signed token always wins on conflicts.
Providers that advertise no userinfo endpoint are left alone rather than failing
the login.

## Administrator rights

Group memberships are always read from the `groups` claim, which accepts either a
list of strings or a space separated string. Only the name of the group that
grants administrator access is configurable, defaulting to
`home_assistant_admin`. Clearing it turns group mapping off entirely.

On every login:

- Gaining the admin group promotes the account.
- Losing it demotes the account, but only if the group was seen on the previous
  login. `OidcSession.is_admin` is what remembers that, which is why the sync has
  to run before the session is rewritten.
- Ending the last session that granted the admin group removes only that group.
  Owner status and unrelated Home Assistant groups remain untouched.
- An account that has never been seen in the admin group is left alone, so an
  administrator appointed inside Home Assistant keeps their rights until the
  identity provider claims authority by showing the group once.
- The owner is never demoted. `User.is_admin` is `is_owner or ...`, and stripping
  the owner's group could leave the instance without an administrator.

Two consequences worth stating plainly: a demotion affects the whole Home
Assistant account, not just access through this provider, and a promoted user is
in two groups until the admin group is taken away again.

Only the admin group is added or removed. Every other membership is left in
place, so a read only user who is briefly an administrator returns to read only
rather than being widened to the regular user group. Permissions are the merge of
all a user's group policies, so replacing the membership wholesale would silently
change access.

## Session lifetime and revalidation

The problem this solves: credentials are only validated during login, which
produces a long lived refresh token. Without further checks, disabling an account
at the identity provider would never reach Home Assistant.

Each session carries a `revalidate_after` deadline. A background task scans due
sessions every minute and silently refreshes them once they are halfway to it,
using the stored identity provider refresh token. This leaves retry margin even
at the minimum five-minute lifetime. A successful refresh pushes the deadline
out; an ID token in the refresh response is verified and must describe the same
subject. If refresh fails with `invalid_grant`, the session and every Home
Assistant refresh token derived from it are dropped immediately. A session with
no external refresh token is dropped at its hard deadline. Until then,
`async_validate_refresh_token` rejects attempts made after the deadline and sends
the user back through the identity provider.

Deliberate choices:

- Revalidation proves the session is still alive and nothing more. It does not
  re-read claims, so a refresh never changes a name or a group.
- A rotated external refresh token is stored before validating an accompanying
  ID token, without extending the deadline. This preserves ownership if key
  discovery is temporarily unavailable. A verified subject mismatch still ends
  the session immediately.
- Refresh tokens returned to an aborted login are revoked. A successful login
  also revokes the external refresh token that its new session replaces.
- Credential removal invalidates the local session and tokens before scheduling
  best-effort provider revocation. Network delay cannot postpone unlinking, and
  a login holding a removed credential cannot commit a replacement session.
- Long lived access tokens are exempt. They never expire by design and have to be
  revoked by hand.
- The 90 day sliding `expire_at` on Home Assistant refresh tokens is untouched.
- A lock guards against overlapping passes. `async_track_time_interval`
  reschedules before running the job, so a slow identity provider could otherwise
  refresh the same session twice and burn a rotating refresh token.
- Replacing any OIDC configuration invalidates existing sessions and local
  tokens. In-flight logins are tied to the configuration generation that started
  them and cannot commit credentials after an administrator changes it.

## Transport and token security

- Every endpoint taken from the discovery document must be HTTPS, including
  `userinfo_endpoint` and `revocation_endpoint`, which carry bearer and refresh
  tokens.
- No outbound request follows redirects. A redirect would defeat the HTTPS check
  on the URL, and a 307 or 308 from the token endpoint would replay the client
  secret to the new target.
- The discovery issuer must exactly match the configured issuer. A trailing
  slash is part of the identifier, so accepting either spelling would weaken
  issuer binding. Providers whose issuer ends in a slash remain supported when
  that exact identifier is configured.
- PKCE always uses `S256`. A provider that advertises challenge methods without
  it is refused rather than silently downgraded, since `plain` offers no real
  protection.
- Token responses have to be labelled `Bearer`, compared case insensitively. The
  access token is sent to the userinfo endpoint as a bearer, so a token the
  provider meant to be used another way would be misused.
- ID token algorithms are restricted to an allowlist intersected with what the
  provider advertises. `none` and the HMAC family are never accepted.
- `aud`, `azp`, `nonce`, `exp` and `iat` are all verified, with a small leeway for
  clock skew. `at_hash` is verified when present, using constant time comparison.
  EdDSA is excluded from `at_hash` verification because OIDC does not pin a hash
  for it.
- Client authentication prefers `client_secret_basic`, which RFC 6749 makes the
  default, and falls back to `client_secret_post` only when it is advertised.
  Explicitly unsupported methods fail before the secret is sent. An omitted
  write-only secret is retained only while issuer and client ID stay unchanged.
- Unknown key IDs trigger a JWKS refetch, rate limited by a cooldown so a forged
  `kid` cannot be used to hammer the provider.
- The store is written with `private=True` and atomic writes, since it holds
  identity provider refresh tokens and the client secret.
- Stored configuration and session fields are validated during eager provider
  initialization. Malformed sections are discarded, and sessions without a
  matching credential and subject are pruned before revalidation starts.

## Known gaps

- Back-channel and front-channel logout are not implemented. Sign out is driven
  by revalidation instead.
