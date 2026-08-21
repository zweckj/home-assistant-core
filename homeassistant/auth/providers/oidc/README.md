---
title: OpenID Connect auth provider
description: Security and design decisions for the Home Assistant OIDC auth provider
---

Why this provider is built the way it is, so the trade-offs are not relitigated.

## Scope

- Configured entirely from the UI via `components/config/auth_provider_oidc.py`. No YAML beyond enabling it.
- Enabled by default in `core_config.py`, hidden from the login screen until an issuer is configured.
- A configurable name overrides `AuthProvider.name` and is what `/auth/providers` reports, so the login screen can offer a recognisable provider instead of "OpenID Connect".
- UI and translated abort reasons live in the frontend repository.

## Dependencies

- PyJWT plus aiohttp only; no new dependency. Authlib was rejected because its async client is httpx-based (a second HTTP stack in core) and `authlib.jose` is deprecated in favour of `joserfc`.
- `jwt.PyJWKClient` must never be used: it fetches over blocking urllib. JWKS is fetched with aiohttp and passed to `jwt.PyJWKSet.from_dict()`.

`helpers/config_entry_oauth2_flow.py` is not reusable for authentication:

- `async_get_redirect_uri()` returns the `my.home-assistant.io` redirector whenever `my` is loaded (part of `default_config`), routing login codes through a third party. It also hardcodes `/auth/external/callback`, bound to the config entry flow manager.
- `LocalOAuth2ImplementationWithPkce` generates one `code_verifier` per instance; PKCE has to be per login attempt.
- `_encode_jwt` signs with a hass-global secret and emits no `exp`, so states never expire.
- `_token_request` maps every 4xx to a reauth error by status and discards the body's `error`, losing the `invalid_grant` distinction this provider needs.
- Only `client_secret_post` is supported.
- Importing it from the auth package pulls in 104 extra modules including `bleak`, and the chain reaches back into `homeassistant.auth`.

Extracting a shared token-request helper would be a reasonable follow-up PR.

## Login flow

- Authorization code flow with PKCE `S256`, with or without a client secret.
- The browser leaves Home Assistant and returns to `/auth/oidc/callback`, registered by the `auth` component. The callback validates state, flow existence, browser, IP and the relying client's redirect URI, then redirects to `/auth/authorize?flow_id=...&auth_callback=1` for a final frontend post.
- `EXTERNAL_STEP` may only move to another external step or to `EXTERNAL_STEP_DONE`; aborting raises `ValueError`. So `async_step_authorize` records failures and `async_step_finish` reports them.
- `EXTERNAL_STEP_DONE` needs a second `async_configure` call to reach `CREATE_ENTRY` — that is the final frontend post.
- `state` is a JWT signed with a per-process secret, expiring in five minutes. Restart only invalidates in-flight logins. `nonce` and `code_verifier` never leave the server.
- A signed state only proves a flow existed, so the flow is also bound to its browser by a cookie named per flow ID, required by both the callback and the final post. Per-flow names keep simultaneous logins independent; keeping it through the final post stops another browser on the same IP finishing the flow. Without it, a delivered callback URL could sign a victim into an account they never authenticated as.
- That cookie is `HttpOnly`, scoped to `/auth`, and `SameSite=Lax` — `Strict` would strip it from the identity provider's cross-site top-level navigation.
- Home Assistant authorization codes are bound to their purpose: a `/auth/link_user` code cannot be exchanged at `/auth/token`, and a wrong-endpoint attempt does not consume it. Unused codes expire after ten minutes, taking any unlinked session and external refresh token with them.

## Identity and account mapping

- The credential key is the verified `iss` and `sub` pair. Per OIDC Core 5.7 a subject is only unique within an issuer, so binding both stops a repointed identity provider inheriting existing accounts.
- The subject claim is not configurable: another signed claim can still be reassignable, turning reassignment into account takeover.
- Nothing else is an identifier. Matching by `preferred_username` was removed — 5.7 states it is neither unique nor stable, which made it a takeover vector.
- Automatic account creation is off by default. The provisioning check necessarily runs after the code exchange, so a login carrying the `link_user` context still gets credentials for `/auth/link_user` to attach. Without that carve-out nobody could get in on a fresh install.
- Linking compares nothing: whatever identity authenticates at the provider is attached to the signed-in account, and the Home Assistant display name is left alone.
- `config/auth_provider/oidc/unlink` detaches the caller's own identity. It is not admin-only, since linking is self-service too, but it refuses unless the account also has a password login, and refuses while `allow_auto_create` is on because the next sign-in would relink. The password is matched on `Credentials.auth_provider_type` rather than by importing that provider, so the two stay independent.

## Claims

| Claim | Configurable | Read when |
| --- | --- | --- |
| Subject | No, always `sub` | Every login, ID token only |
| Username | Yes, `username_claim` | Account creation |
| Display name | Yes, `display_name_claim` | Account creation |
| Groups | No, always `groups` | Every login |

- Display name applies only at creation, so a rename inside Home Assistant is permanent.
- Claim names are plain key lookups; nested paths are unsupported.
- Userinfo is consulted only when creating an account whose ID token lacks `username_claim` or `display_name_claim`. Returning users cost no request.
- OIDC Core 5.3.2 requires discarding a userinfo response unless its `sub` matches the ID token exactly, since a substituted access token would otherwise import another user's claims. Enforced before merging; a mismatch or missing `sub` aborts the login.
- Conditional fetching does not weaken that: 5.3.2 governs how a response is used, not whether one is requested. Comparison is a plain `!=` on decoded strings — the code point equality Core 14 mandates. Unicode normalization must not be applied.
- Merge order is `userinfo | id_token`, so the signed token wins. A provider advertising no userinfo endpoint is skipped rather than failed.

## Administrator rights

Groups come from the `groups` claim (list of strings, or space separated). Only the admin group name is configurable, defaulting to `home_assistant_admin`; clearing it disables group mapping.

- Gaining the group promotes; losing it demotes, but only if the group was seen on the previous login. `OidcSession.is_admin` remembers that, so the sync must run before the session is rewritten.
- Ending the last session that granted the group removes only that group.
- An account never seen in the group is left alone, so an administrator appointed inside Home Assistant keeps their rights until the identity provider claims authority by showing the group once.
- The owner is never demoted: `User.is_admin` is `is_owner or ...`, and stripping it could leave the instance with no administrator.
- Only the admin group is added or removed. Permissions are the merge of all group policies, so replacing membership wholesale would silently change access — a read-only user who is briefly an administrator returns to read-only.
- Consequences: a demotion affects the whole Home Assistant account, not just this provider, and a promoted user sits in two groups until demoted.

## Session lifetime and revalidation

Credentials are only checked during login, which yields a long-lived refresh token. Without more, disabling an account at the identity provider would never reach Home Assistant.

- Each session carries a `revalidate_after` deadline. A background task scans due sessions every minute and refreshes silently once halfway there, leaving retry margin even at the five-minute minimum.
- Success pushes the deadline out. An ID token in the refresh response is verified and must describe the same subject.
- `invalid_grant` drops the session and every Home Assistant refresh token derived from it. A session with no external refresh token is dropped at its hard deadline; until then `async_validate_refresh_token` rejects late attempts.
- Revalidation only proves liveness. It never re-reads claims, so a refresh cannot change a name or a group.
- A rotated external refresh token is stored before validating an accompanying ID token and without extending the deadline, preserving ownership if key discovery is briefly unavailable. A verified subject mismatch still ends the session at once.
- Refresh tokens returned to an aborted login are revoked, as is the external refresh token a successful login replaces.
- Credential removal invalidates the local session and tokens before best-effort provider revocation, so network delay cannot postpone unlinking.
- Long-lived access tokens are exempt; they never expire by design and must be revoked by hand.
- The 90 day sliding `expire_at` on Home Assistant refresh tokens is untouched.
- A lock guards overlapping passes: `async_track_time_interval` reschedules before running, so a slow provider could otherwise refresh a session twice and burn a rotating token.
- Replacing any configuration invalidates existing sessions and local tokens. In-flight logins are tied to the configuration generation that started them.

## Transport and token security

- Every discovery endpoint must be HTTPS, including `userinfo_endpoint` and `revocation_endpoint`, which carry bearer and refresh tokens.
- No outbound request follows redirects: a redirect defeats the HTTPS check, and a 307 or 308 from the token endpoint would replay the client secret.
- The discovery issuer must match the configured issuer exactly. A trailing slash is part of the identifier, so accepting either spelling would weaken issuer binding.
- PKCE is always `S256`. A provider advertising challenge methods without it is refused rather than downgraded to `plain`.
- Token responses must be labelled `Bearer`, compared case insensitively, because the access token is sent to userinfo as a bearer.
- ID token algorithms are an allowlist intersected with what the provider advertises; `none` and the HMAC family are never accepted.
- `aud`, `azp`, `nonce`, `exp` and `iat` are verified with a small clock-skew leeway. `at_hash` is verified when present using constant-time comparison; EdDSA is excluded because OIDC pins no hash for it.
- Client authentication prefers `client_secret_basic` (the RFC 6749 default), falling back to `client_secret_post` only when advertised. Explicitly unsupported methods fail before the secret is sent. An omitted write-only secret is retained only while issuer and client ID are unchanged.
- Unknown key IDs trigger a JWKS refetch behind a cooldown, so a forged `kid` cannot hammer the provider.
- The store uses `private=True` and atomic writes; it holds external refresh tokens and the client secret.
- Stored configuration and sessions are validated during eager initialization. Malformed sections are discarded and sessions without a matching credential and subject are pruned before revalidation starts.

## Known gaps

- Back-channel and front-channel logout are not implemented; sign out is driven by revalidation.
