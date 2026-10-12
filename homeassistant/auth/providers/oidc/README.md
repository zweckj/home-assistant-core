---
title: Identity provider engine
description: Security and design decisions for signing in to Home Assistant with external identity providers
---

Why the engine is built the way it is, so the trade-offs are not relitigated.

Decisions come first: each one has a reason, and reversing it needs a better reason. What follows them is reference material, describing the shape of the implementation so it can be checked without reading every module.

## Decisions

### One audited engine, configured by integrations

- All protocol, account and session logic for signing in with an external identity provider lives in this package. Each identity provider is an integration that contributes configuration only: a config flow and an `identity_provider.py` platform returning a data-only `IdentityProvider` spec.
- The audit boundary is this package, the child provider hook in `homeassistant/auth/__init__.py` and `homeassistant/auth/providers/__init__.py`, `homeassistant/components/auth/` (views, the authorization code store, the platform bridge and the public exports), `homeassistant/components/config/auth_provider_oidc.py`, and the token request and client authentication helpers the engine shares from `homeassistant/helpers/oauth2.py`. Identity provider integrations are reviewed as configuration.
- Adding an identity provider must not touch this package. One that needs a capability the spec cannot express, such as `private_key_jwt` or `response_mode=form_post`, is an engine change and needs a new audit.
- The spec is a public API because custom integrations can use it, so it changes additively.

### The spec is data, and integration code never runs in the auth path

- `IdentityProvider`, `OpenIDConnect`, `OAuth2Profile`, `AccountPolicy` and the claim rules are frozen, slotted dataclasses and enums without callables, imported from `homeassistant.components.auth`.
- `get_identity_provider(data, options)` is synchronous and receives the config entry data and options only, never `hass`, which makes I/O an obvious violation. The bridge calls it when an entry loads or changes, never while signing in, linking, validating tokens or revalidating sessions.
- `validate_identity_provider` checks exact types, so a `str` subclass or an `int` passed as a `bool` is refused, and returns a copy with read-only mappings. It enforces:
  - HTTPS URLs with a host and without credentials or a fragment, for the issuer and every configured endpoint;
  - an issuer template with exactly one placeholder that is a whole path segment, plus an `issuer_claim` to fill it; aliases cannot be templates;
  - `openid` among the OpenID Connect scopes, and claim rules that are `Equals`, `NotEquals` or a non-empty `OneOf`;
  - no reserved headers, such as `Authorization`, `Cookie`, `Host` or the framing headers, on profile requests;
  - `PROVISION` only with `OpenIDConnect` and a revalidation interval between five minutes and thirty days, while `LINK` refuses an interval. Values out of bounds are rejected, not clamped.
- Registration builds the protocol client before anything is stored, so a spec the client refuses fails with `invalid_spec` instead of at the first sign-in.
- `async_validate_identity_provider` runs the same checks and, for OpenID Connect, fetches the discovery document, so a config flow rejects a spec before creating the entry. Every failure carries a stable `IdentityProviderError.reason`.
- The hassfest `identity_provider` plugin checks core integrations: the manifest (`dependencies: [auth]`, `config_flow`, `integration_type: service`, no requirements), an import allowlist applied to every module of the integration (no aiohttp, no network helpers, no `homeassistant.auth` internals and no relative import leaving the package), forbidden builtins such as `open` and `exec`, and the shape of `identity_provider.py`. It is a review aid, not a sandbox.
- Custom integrations may contribute identity providers. hassfest never sees them, so runtime validation is their only check, and a warning is logged once per integration. Installing one is the administrator's trust decision, like any custom integration.

### Root and child providers

- The root provider `(oidc, None)` is enabled by default in `core_config.py`; a custom `auth_providers` list needs `- type: oidc`. It is never offered on the login screen.
- Every identity provider config entry is a child provider `(oidc, <entry_id>)`, resolved through `AuthProvider.child_providers` and `async_get_child_provider`. There is no general registration API, so integrations cannot inject provider code.
- The root stores a registry of identity providers (entry ID, domain, account policy and trust key) and creates a dormant child for each at startup. HTTP serves requests before config entries are set up, and existing tokens have to resolve and validate before, or without, the integration loading.
- A dormant child starts no sign-in or link flow and does not count as a login method.
- Names and icons are not stored. A child is named after its config entry title, passed in at runtime, and `/auth/providers` reports its `domain` so the frontend can show the brand icon.

### Account policies

The spec declares what an identity may be used for; the engine enforces it.

- `LINK`, the default:
  - only a signed-in user that is not system generated can start a link flow, and the resulting code only links to that user;
  - signing in with an identity that is not linked aborts `user_not_allowed`, and `/auth/token` answers 403 as a backstop;
  - the external refresh token is revoked straight away and nothing is stored, so there is nothing to revalidate. A linked identity is another way to sign in, like a password or a passkey;
  - Home Assistant multi-factor authentication applies after the external sign-in.
- `PROVISION` adds:
  - signing in with an unknown identity creates a user, never an owner, in `system-users` unless the ID token grants the admin group;
  - a JWKS-verified ID token is mandatory, so `OAuth2Profile` cannot provision;
  - revalidation is mandatory, and multi-factor authentication is left to the identity provider;
  - its identities cannot be unlinked, because the next sign-in would provision a new user.
- The remaining risk is an integration declaring `PROVISION` for an identity provider anyone can register with, such as Google, GitHub or Microsoft `common`. Integrations default to `LINK` and offer `PROVISION` only as an explicit option where one organisation controls the accounts, such as the administrator's own issuer or a single Microsoft tenant. Spec snapshot tests make such a change visible in review.

### Identity and account mapping

- An OpenID Connect credential is keyed by the canonical issuer and `sub`. Per OIDC Core 5.7 a subject is only unique within an issuer, so binding both stops a repointed identity provider inheriting existing accounts.
- Aliases are accepted in `iss` but never stored; credentials always carry the canonical issuer. A templated issuer stores the filled-in value, so subjects of different tenants stay apart. The filling claim must match a conservative character pattern, and `iss` must equal the filled template exactly.
- The subject claim is not configurable: another signed claim may be reassignable, turning reassignment into account takeover.
- Nothing else is an identifier. Matching by `preferred_username` was removed; 5.7 states it is neither unique nor stable, which made it a takeover vector.
- An `OAuth2Profile` credential is keyed by the origin of the profile URL and the configured profile field. That field has to be a non-empty string or an integer; a boolean is refused. The profile endpoint is only reached with the access token from the same exchange, but this is weaker than a signed ID token, which is why these identities can only be linked.
- `required_claims` are checked on the verified ID token at every sign-in and on every refreshed ID token; a refreshed token that fails them ends the session.
- `account_name` is shown to the user next to the linked identity and refreshed at every sign-in. It is never used for matching.
- OIDC Core 5.3.2 requires discarding a userinfo response unless its `sub` matches the ID token exactly, since a substituted access token would otherwise import another user's claims. A mismatch or a missing `sub` aborts the login.
- Fetching userinfo only when it is needed does not weaken that: 5.3.2 governs how a response is used, not whether one is requested. The comparison is a plain `!=` on decoded strings, the code point equality Core 14 mandates. Unicode normalization must not be applied.
- Linking compares nothing: whatever identity authenticates at the provider is attached to the signed-in account, and the Home Assistant display name is left alone.
- `config/auth_provider/oidc/unlink` detaches one of the caller's own `LINK` identities. It is not admin-only, since linking is self-service too.
- Unlinking refuses unless the account keeps a login it can still use, which is `AuthManager.async_has_other_login_method`, not a rule of this provider's own. A credential of a dormant or removed provider does not count. Any provider that lets a user delete a credential owes the same check, or an account can be locked out from the other side.

### Lifecycle

The bridge follows config entries of every domain with an `identity_provider` platform through `SIGNAL_CONFIG_ENTRY_CHANGED`, so integrations need no listener code and their setup is a no-op.

| Entry state | Login button | New sign-in or link | Existing sessions | Links |
| --- | --- | --- | --- | --- |
| Loaded, spec accepted | shown | yes | valid, `PROVISION` revalidated | kept |
| Not loaded yet, failed, or integration missing | hidden | no | `LINK` valid, `PROVISION` until the revalidation deadline | kept |
| Spec rejected | hidden | no | as not loaded, plus a repair issue | kept |
| Disabled | hidden | no | ended | kept |
| Trust key changed | shown | yes | ended | kept |
| Removed | gone | no | ended | removed, plus a repair issue naming users left without a login |
| Engine missing from `auth_providers` | – | – | – | config flows abort, existing entries get a repair issue |

- The trust key is a digest of the client ID, client secret, protocol settings, account policy and `allow_insecure_transport`. The account name, username and display name claims or fields only label or seed an account, so they are left out with the revalidation interval, and changing them keeps sessions. Rotating the client secret does end them.
- Ending sessions revokes their external refresh tokens with the client of the last activation, which the child keeps after it is suspended. When the key changes, the old client revokes before the new spec takes over.
- Flows capture the configuration generation when they start and abort `configuration_changed` when it moved before they finish. Suspending bumps the generation too.
- Removal suspends the child first, so logins in flight abort, then collects the users left without another login, ends the sessions, removes the credentials and drops the registry record. After startup, registry records without a config entry are removed the same way.
- An authorization code is refused once its provider is gone. A refresh token used for the first time while its child is suspended or dormant is refused as well, so a code minted before the suspension cannot start a session. Tokens that were already used keep working while the integration loads.

### Binding a login to its browser

- `state` is a JWT signed with a per-process secret, expiring in five minutes. A restart only invalidates in-flight logins. `nonce` and `code_verifier` never leave the server.
- A signed state only proves a flow existed, so the flow is also bound to its browser by a cookie named per flow ID, required by both the callback and the final post. Without it, a delivered callback URL could sign a victim into an account they never authenticated as.
- Per-flow cookie names keep simultaneous logins independent, and keeping the cookie through the final post stops another browser on the same IP finishing the flow.
- That cookie is `HttpOnly`, scoped to `/auth`, and `SameSite=Lax`; `Strict` would strip it from the identity provider's cross-site top-level navigation.
- Home Assistant authorization codes are bound to their purpose: a `/auth/link_user` code cannot be exchanged at `/auth/token`, and a wrong-endpoint attempt does not consume it. Starting a link flow needs the user's bearer token, and its code only links to that user. Unused codes expire after ten minutes, and revoking every session of a credential, which unlinking and ending identity provider sessions do, drops its unredeemed codes with them. The worker pass after that drops the session and external refresh token of a login whose code was never exchanged, including for a suspended child.

### Administrator rights

Only `PROVISION` identity providers can grant administrator rights, and only when the spec names an `admin_group`. There is no default group name. The group comes from the verified ID token's `groups` claim (a list of strings, or space separated), never from userinfo.

- Gaining the group promotes; losing it demotes, but only if the group was seen before. `OidcSession.is_admin` remembers that, so the sync must run before the session is rewritten.
- An account never seen in the group is left alone, so an administrator appointed inside Home Assistant keeps their rights until the identity provider claims authority by showing the group once.
- The owner is never demoted: `User.is_admin` is `is_owner or ...`, and stripping it could leave the instance with no administrator.
- Only the admin group is added or removed. Permissions are the merge of all group policies, so replacing membership wholesale would silently change access: a read-only user who is briefly an administrator returns to read-only.
- Ending the last session that granted the group removes only that group.
- Consequences: a demotion affects the whole Home Assistant account, not just this provider, and a promoted user sits in two groups until demoted.

### Session lifetime and revalidation

This applies to `PROVISION`. Credentials are only checked during login, which yields a long-lived refresh token. Without more, disabling an account at the identity provider would never reach Home Assistant.

- Each session carries a `revalidate_after` deadline. A worker pass runs every minute and refreshes silently once a session is halfway there, leaving retry margin even at the five-minute minimum.
- That deadline is enforced locally, before any network work. A provider that is unreachable, or that keeps failing, cannot hold a session open past it.
- Success pushes the deadline out. An ID token in the refresh response is verified and must describe the same subject and pass the claim rules; otherwise the session ends at once.
- Revalidation proves liveness and re-applies authorization. A refreshed ID token carrying `groups` is authoritative and can promote or demote. One that omits them says nothing about entitlement, so the grant is left for the next interactive login rather than read as renewed or withdrawn.
- The display name and username are read once, while the account is created, so a refresh never renames anybody.
- `invalid_grant` drops the session and every Home Assistant refresh token derived from it. A session with no external refresh token is dropped at its hard deadline; until then `async_validate_refresh_token` rejects late attempts.
- A rotated external refresh token is stored before an accompanying ID token is validated, and without extending the deadline, preserving ownership if key discovery is briefly unavailable.
- Refresh tokens returned to an aborted login are revoked, as is the external refresh token a successful login replaces.
- Credential removal invalidates the local session and tokens before best-effort provider revocation, so network delay cannot postpone unlinking.
- Long-lived access tokens are exempt; they never expire by design and must be revoked by hand.
- The 90 day sliding `expire_at` on Home Assistant refresh tokens is untouched.
- A lock guards overlapping passes: `async_track_time_interval` reschedules before running, so a slow provider could otherwise refresh a session twice and burn a rotating token. A pass that finishes late checks that its session is still the current one, so it cannot undo a login that completed while it ran.

### What ending a session reaches

Ending the sessions of an identity provider removes every Home Assistant refresh token of its credentials, through the same `async_remove_refresh_token` path an ordinary revocation takes, so open connections close with it. For `LINK` that means everybody who signed in through it signs in again. That is narrower than deactivating the account, deliberately.

- Disabling somebody at the identity provider does not deactivate their Home Assistant user. A local password or a passkey remains a login method of its own, long-lived access tokens are exempt by design, and tokens carrying no credential are never selected because nothing ties them to this provider. Offboarding that has to close every door means removing the user, not the link.
- How quickly a revocation upstream is noticed follows from the interval: at a 24 hour interval the first refresh attempt lands after twelve hours. Shorten it where a tighter bound matters. A refresh that succeeds proves the grant still works, not that the account is still entitled to anything.
- One session is stored per Home Assistant credential rather than per browser or device, and a new login replaces the token that credential shares. Signing out therefore cannot be aimed at a single device.
- Permission to link a credential is not assurance at sign-in. Neither is a successful revalidation. Step-up authentication is a separate concern and must not be folded into this lifecycle.

### Transport, tokens and storage

- Every endpoint must be HTTPS, including `userinfo_endpoint` and `revocation_endpoint` from discovery, which carry bearer and refresh tokens, and the profile endpoint.
- No outbound request follows redirects: a redirect defeats the HTTPS check, and a 307 or 308 from the token endpoint would replay the client secret.
- The browser flow itself must be HTTPS unless the request arrived over the internal URL, since the tokens it carries are as exposed as the ones on the back channel.
- A spec can waive all three HTTPS rules with `allow_insecure_transport`, for an identity provider on a trusted network that cannot be given a certificate; integrations should offer it in advanced mode only. It only relaxes the scheme: endpoints still need a host and may not carry credentials or a fragment. It is part of the trust key, so toggling it ends that identity provider's sessions.
- The discovery document's issuer must match the configured issuer exactly. A trailing slash is part of the identifier, so accepting either spelling would weaken issuer binding.
- PKCE is always `S256`. A provider advertising challenge methods without it is refused rather than downgraded to `plain`.
- Token responses must be labelled `Bearer`, compared case insensitively, because the access token is sent to userinfo as a bearer. A 200 without a bearer access token is a failure too, because GitHub answers errors with 200. A 429 is retried like a 5xx, and any other 4xx from the token endpoint counts as a rejected grant.
- ID token algorithms are an allowlist intersected with what the provider advertises; `none` and the HMAC family are never accepted.
- A key is only used when the provider publishes it for verifying signatures, and a key that declares an algorithm is held to it.
- `aud`, `azp`, `nonce`, `exp` and `iat` are verified with a small clock-skew leeway. `at_hash` is verified when present using constant-time comparison; EdDSA is excluded because OIDC pins no hash for it.
- OpenID Connect client authentication prefers `client_secret_basic` (the RFC 6749 default), falling back to `client_secret_post` only when advertised. Explicitly unsupported methods fail before the secret is sent. `OAuth2Profile` has no discovery, so its spec names the method.
- Unknown key IDs trigger a JWKS refetch behind a cooldown, so a forged `kid` cannot hammer the provider.
- The store uses `private=True` and atomic writes. It holds the identity provider registry and the sessions with their external refresh tokens, but never client secrets; those live in config entries.
- Stored records and sessions are validated during eager initialization. Unreadable entries are discarded, and sessions without a registered identity provider or without a credential of the same subject are pruned before revalidation starts.

## How it works

### Integrations

No identity provider integration ships with the engine; each one is added separately. A generic OpenID Connect integration configures any issuer through discovery, and provider specific integrations build on the same spec: issuer aliases (Google), an issuer template filled from a claim (Microsoft tenants) and `OAuth2Profile` for providers without OpenID Connect (GitHub).

- Config flows subclass `IdentityProviderConfigFlow` from the `auth` component and declare their forms, title and spec builder; hassfest rejects any other config flow in a sign-in integration. The base aborts when the engine is not in `auth_providers` or no URL is available, shows the redirect URIs to register, validates every spec with `async_validate_identity_provider` before creating or updating an entry, maps validation reasons to the shared form errors and runs the options flow. An integration that derives the entry from the input, such as through discovery with `async_discover_identity_provider`, overrides `async_resolve_setup` only.
- Reconfiguring never shows the stored client secret and always asks for it again; an empty secret turns the entry into a public client. An identity provider with pairwise subjects, such as Microsoft, keys them by client ID, so its reconfigure form only takes the secret.
- Tests snapshot the spec for representative entries and run a sign-in and a link through the real engine against the fake identity providers in `tests/components/auth/common.py`.
- `config/auth_provider/oidc/list` returns the active identity providers and the caller's linked identities, including those of dormant providers marked unavailable. `config/auth_provider/oidc/unlink` detaches one of them.
- The login buttons, the linked accounts in the profile and translated abort reasons live in the frontend repository.

### Login flow

- Authorization code flow with PKCE `S256`, with or without a client secret.
- The browser leaves Home Assistant and returns to `/auth/login_callback`, the shared callback the `auth` component registers for any login flow with an external step. The callback validates state, flow existence, browser, IP and the relying client's redirect URI, then redirects to `/auth/authorize?flow_id=...&auth_callback=1` for a final frontend post.
- `EXTERNAL_STEP` may only move to another external step or to `EXTERNAL_STEP_DONE`; aborting raises `ValueError`. So `async_step_authorize` records failures and `async_step_finish` reports them.
- `EXTERNAL_STEP_DONE` needs a second `async_configure` call to reach `CREATE_ENTRY`; that is the final frontend post.
- An `OAuth2Profile` flow exchanges the code, reads the profile with the access token and discards the token.

### Claims

| Value | Set by | Read when |
| --- | --- | --- |
| Subject | Always `sub`; `subject_field` for `OAuth2Profile` | Every login, ID token or profile only |
| Account name | `account_name_claim` or `account_name_field` | Every login, display only |
| Username | `username_claim` | Account creation |
| Display name | `display_name_claim` | Account creation |
| Groups | Always `groups`, only with `admin_group` | Verified ID tokens at login and refresh |

- Display name applies only at creation, so a rename inside Home Assistant is permanent.
- Claim names are plain key lookups; nested paths are unsupported.
- Userinfo is consulted only when creating an account whose ID token lacks `username_claim` or `display_name_claim`. Returning users cost no request.
- Profile enrichment uses `userinfo | id_token`, so the signed token wins. Only username and display name use the enriched claims; identity and administrator grants use the verified ID token. A provider advertising no userinfo endpoint is skipped rather than failed.

## Known gaps

- Back-channel and front-channel logout are not implemented; sign out is driven by revalidation.
- The last-usable-login check is per provider. Two removals running concurrently in different providers can each count the other as the fallback.
- Step up authentication is not offered. Proving an identity again means a full browser redirect to the identity provider, so `support_step_up` stays off and a sensitive action has to be confirmed with another provider the account is linked to.
- A `LINK` sign-in code minted just before a trust key change that keeps the child active can still be exchanged within its ten minutes. `PROVISION` is not affected, because ending the sessions leaves the code without the session it needs.
- A link code minted before its identity provider was suspended can still be redeemed. The linked identity cannot sign in until the provider is active again.
- `OAuth2Profile` access tokens are discarded, not revoked; GitHub offers no standard revocation endpoint.
- Login buttons only appear once the identity provider integrations are loaded. Existing sessions keep working in the meantime.
- The repair issue naming users left without a login after a removal stays until it is dismissed.
