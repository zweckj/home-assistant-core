---
title: OpenID Connect auth provider
description: Security and design decisions for the Home Assistant OIDC auth provider
---

Why this provider is built the way it is, so the trade-offs are not relitigated.

Decisions come first: each one has a reason, and reversing it needs a better reason. What follows them is reference material, describing the shape of the implementation so it can be checked without reading every module.

## Decisions

### Dependencies

- PyJWT plus aiohttp only; no new dependency. Authlib was rejected because its async client is httpx-based (a second HTTP stack in core) and `authlib.jose` is deprecated in favour of `joserfc`.
- `jwt.PyJWKClient` must never be used: it fetches over blocking urllib. JWKS is fetched with aiohttp instead.

`helpers/config_entry_oauth2_flow.py` is not reusable for authentication:

- `async_get_redirect_uri()` returns the `my.home-assistant.io` redirector whenever `my` is loaded (part of `default_config`), routing login codes through a third party. It also hardcodes `/auth/external/callback`, bound to the config entry flow manager.
- `LocalOAuth2ImplementationWithPkce` generates one `code_verifier` per instance; PKCE has to be per login attempt.
- `_encode_jwt` signs with a hass-global secret and emits no `exp`, so states never expire.
- `_token_request` maps every 4xx to a reauth error by status and discards the body's `error`, losing the `invalid_grant` distinction this provider needs.
- Only `client_secret_post` is supported.
- Importing it from the auth package pulls in 104 extra modules including `bleak`, and the chain reaches back into `homeassistant.auth`.

Extracting a shared token-request helper would be a reasonable follow-up PR.

### Identity and account mapping

- The credential key is the verified `iss` and `sub` pair. Per OIDC Core 5.7 a subject is only unique within an issuer, so binding both stops a repointed identity provider inheriting existing accounts.
- The subject claim is not configurable: another signed claim can still be reassignable, turning reassignment into account takeover.
- Nothing else is an identifier. Matching by `preferred_username` was removed — 5.7 states it is neither unique nor stable, which made it a takeover vector.
- OIDC Core 5.3.2 requires discarding a userinfo response unless its `sub` matches the ID token exactly, since a substituted access token would otherwise import another user's claims. A mismatch or a missing `sub` aborts the login.
- Fetching userinfo only when it is needed does not weaken that: 5.3.2 governs how a response is used, not whether one is requested. The comparison is a plain `!=` on decoded strings — the code point equality Core 14 mandates. Unicode normalization must not be applied.
- Automatic account creation is off by default. The provisioning check necessarily runs after the code exchange, so a login carrying the `link_user` context still gets credentials for `/auth/link_user` to attach. Without that carve-out nobody could get in on a fresh install.
- Linking compares nothing: whatever identity authenticates at the provider is attached to the signed-in account, and the Home Assistant display name is left alone.
- `config/auth_provider/oidc/unlink` detaches the caller's own identity. It is not admin-only, since linking is self-service too, but it refuses while `allow_auto_create` is on because the next sign-in would relink.
- Unlinking also refuses unless the account keeps a login it can still use, which is `AuthManager.async_has_other_login_method`, not a rule of this provider's own. A credential whose provider is no longer configured does not count, and neither does another identity from this provider when every one of them is being detached at once. Any provider that lets a user delete a credential owes the same check, or an account can be locked out from the other side.

### Binding a login to its browser

- `state` is a JWT signed with a per-process secret, expiring in five minutes. A restart only invalidates in-flight logins. `nonce` and `code_verifier` never leave the server.
- A signed state only proves a flow existed, so the flow is also bound to its browser by a cookie named per flow ID, required by both the callback and the final post. Without it, a delivered callback URL could sign a victim into an account they never authenticated as.
- Per-flow cookie names keep simultaneous logins independent, and keeping the cookie through the final post stops another browser on the same IP finishing the flow.
- That cookie is `HttpOnly`, scoped to `/auth`, and `SameSite=Lax` — `Strict` would strip it from the identity provider's cross-site top-level navigation.
- Home Assistant authorization codes are bound to their purpose: a `/auth/link_user` code cannot be exchanged at `/auth/token`, and a wrong-endpoint attempt does not consume it. Unused codes expire after ten minutes, taking any unlinked session and external refresh token with them.

### Administrator rights

Groups come from the `groups` claim (list of strings, or space separated). Only the admin group name is configurable, defaulting to `home_assistant_admin`; clearing it disables group mapping.

- Gaining the group promotes; losing it demotes, but only if the group was seen before. `OidcSession.is_admin` remembers that, so the sync must run before the session is rewritten.
- An account never seen in the group is left alone, so an administrator appointed inside Home Assistant keeps their rights until the identity provider claims authority by showing the group once.
- The owner is never demoted: `User.is_admin` is `is_owner or ...`, and stripping it could leave the instance with no administrator.
- Only the admin group is added or removed. Permissions are the merge of all group policies, so replacing membership wholesale would silently change access — a read-only user who is briefly an administrator returns to read-only.
- Ending the last session that granted the group removes only that group.
- Consequences: a demotion affects the whole Home Assistant account, not just this provider, and a promoted user sits in two groups until demoted.

### Session lifetime and revalidation

Credentials are only checked during login, which yields a long-lived refresh token. Without more, disabling an account at the identity provider would never reach Home Assistant.

- Each session carries a `revalidate_after` deadline. A worker pass runs every minute and refreshes silently once a session is halfway there, leaving retry margin even at the five-minute minimum.
- That deadline is enforced locally, before any network work. A provider that is unreachable, or that keeps failing, cannot hold a session open past it.
- Success pushes the deadline out. An ID token in the refresh response is verified and must describe the same subject; a verified mismatch ends the session at once.
- Revalidation proves liveness and re-applies authorization. A refreshed ID token carrying `groups` is authoritative and can promote or demote. One that omits them says nothing about entitlement, so the grant is left for the next interactive login rather than read as renewed or withdrawn.
- The display name and username are read once, while the account is created, so a refresh never renames anybody.
- `invalid_grant` drops the session and every Home Assistant refresh token derived from it. A session with no external refresh token is dropped at its hard deadline; until then `async_validate_refresh_token` rejects late attempts.
- A rotated external refresh token is stored before an accompanying ID token is validated, and without extending the deadline, preserving ownership if key discovery is briefly unavailable.
- Refresh tokens returned to an aborted login are revoked, as is the external refresh token a successful login replaces.
- Credential removal invalidates the local session and tokens before best-effort provider revocation, so network delay cannot postpone unlinking.
- Long-lived access tokens are exempt; they never expire by design and must be revoked by hand.
- The 90 day sliding `expire_at` on Home Assistant refresh tokens is untouched.
- A lock guards overlapping passes: `async_track_time_interval` reschedules before running, so a slow provider could otherwise refresh a session twice and burn a rotating token. A pass that finishes late checks that its session is still the current one, so it cannot undo a login that completed while it ran.
- Replacing any configuration invalidates existing sessions and local tokens. In-flight logins are tied to the configuration generation that started them.

### What ending a session reaches

Ending a session removes it and every Home Assistant token derived from it, through the same `async_remove_refresh_token` path an ordinary revocation takes, so open connections close with it. That is narrower than deactivating the account, deliberately.

- Disabling somebody at the identity provider does not deactivate their Home Assistant user. A local password or a passkey remains a login method of its own, long-lived access tokens are exempt by design, and tokens carrying no credential are never selected because nothing ties them to this provider. Offboarding that has to close every door means removing the user, not the link.
- How quickly a revocation upstream is noticed follows from the interval: at the 24 hour default the first refresh attempt lands after twelve hours. Shorten it where a tighter bound matters. A refresh that succeeds proves the grant still works, not that the account is still entitled to anything.
- One session is stored per Home Assistant credential rather than per browser or device, and a new login replaces the token that credential shares. Signing out therefore cannot be aimed at a single device.
- Permission to link a credential is not assurance at sign-in. Neither is a successful revalidation. Step-up authentication is a separate concern and must not be folded into this lifecycle.

### Transport, tokens and storage

- Every discovery endpoint must be HTTPS, including `userinfo_endpoint` and `revocation_endpoint`, which carry bearer and refresh tokens.
- No outbound request follows redirects: a redirect defeats the HTTPS check, and a 307 or 308 from the token endpoint would replay the client secret.
- The browser flow itself must be HTTPS unless the request arrived over the internal URL, since the tokens it carries are as exposed as the ones on the back channel.
- The discovery issuer must match the configured issuer exactly. A trailing slash is part of the identifier, so accepting either spelling would weaken issuer binding.
- PKCE is always `S256`. A provider advertising challenge methods without it is refused rather than downgraded to `plain`.
- Token responses must be labelled `Bearer`, compared case insensitively, because the access token is sent to userinfo as a bearer.
- ID token algorithms are an allowlist intersected with what the provider advertises; `none` and the HMAC family are never accepted.
- A key is only used when the provider publishes it for verifying signatures, and a key that declares an algorithm is held to it.
- `aud`, `azp`, `nonce`, `exp` and `iat` are verified with a small clock-skew leeway. `at_hash` is verified when present using constant-time comparison; EdDSA is excluded because OIDC pins no hash for it.
- Client authentication prefers `client_secret_basic` (the RFC 6749 default), falling back to `client_secret_post` only when advertised. Explicitly unsupported methods fail before the secret is sent. An omitted write-only secret is retained only while issuer and client ID are unchanged.
- Unknown key IDs trigger a JWKS refetch behind a cooldown, so a forged `kid` cannot hammer the provider.
- The store uses `private=True` and atomic writes; it holds external refresh tokens and the client secret.
- Stored configuration and sessions are validated during eager initialization. Malformed sections are discarded and sessions without a matching credential and subject are pruned before revalidation starts.

## How it works

### Scope and configuration

- Configured entirely from the UI via `components/config/auth_provider_oidc.py`. No YAML beyond enabling it.
- Enabled by default in `core_config.py`, hidden from the login screen until an issuer is configured.
- A configurable name overrides `AuthProvider.name` and is what `/auth/providers` reports, so the login screen can offer a recognisable provider instead of "OpenID Connect".
- UI and translated abort reasons live in the frontend repository.

### Login flow

- Authorization code flow with PKCE `S256`, with or without a client secret.
- The browser leaves Home Assistant and returns to `/auth/login_callback`, the shared callback the `auth` component registers for any login flow with an external step. The callback validates state, flow existence, browser, IP and the relying client's redirect URI, then redirects to `/auth/authorize?flow_id=...&auth_callback=1` for a final frontend post.
- `EXTERNAL_STEP` may only move to another external step or to `EXTERNAL_STEP_DONE`; aborting raises `ValueError`. So `async_step_authorize` records failures and `async_step_finish` reports them.
- `EXTERNAL_STEP_DONE` needs a second `async_configure` call to reach `CREATE_ENTRY` — that is the final frontend post.

### Claims

| Claim | Configurable | Read when |
| --- | --- | --- |
| Subject | No, always `sub` | Every login, ID token only |
| Username | Yes, `username_claim` | Account creation |
| Display name | Yes, `display_name_claim` | Account creation |
| Groups | No, always `groups` | Every login, and every refresh that carries them |

- Display name applies only at creation, so a rename inside Home Assistant is permanent.
- Claim names are plain key lookups; nested paths are unsupported.
- Userinfo is consulted only when creating an account whose ID token lacks `username_claim` or `display_name_claim`. Returning users cost no request.
- Merge order is `userinfo | id_token`, so the signed token wins. A provider advertising no userinfo endpoint is skipped rather than failed.

## Known gaps

- Back-channel and front-channel logout are not implemented; sign out is driven by revalidation.
- The last-usable-login check is per provider. Two removals running concurrently in different providers can each count the other as the fallback.
- Step up authentication is not offered. Proving an identity again means a full browser redirect to the identity provider, so `support_step_up` stays off and a sensitive action has to be confirmed with another provider the account is linked to.

