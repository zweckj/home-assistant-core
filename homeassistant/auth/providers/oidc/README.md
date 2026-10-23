---
title: Identity provider engine
description: Security and design decisions for signing in to Home Assistant with external identity providers
---

Why the engine is built the way it is, so the trade-offs are not relitigated.

Decisions come first: each one has a reason, and reversing it needs a better reason. What follows them is reference material, describing the shape of the implementation so it can be checked without reading every module.

## Decisions

### One audited engine, configured by integrations

- All protocol, account and session logic for signing in with an external identity provider lives in this package. Each identity provider is an integration that contributes configuration: a config flow and an `identity_provider.py` platform returning a data-only `IdentityProvider` spec.
- The audit boundary is this package, the child provider hook in `homeassistant/auth/__init__.py` and `homeassistant/auth/providers/__init__.py`, `homeassistant/components/auth/` (views, the authorization code store, the platform bridge and the public exports), `homeassistant/components/config/auth_provider_oidc.py`, and the token request and client authentication helpers the engine shares from `homeassistant/helpers/oauth2.py`. Identity provider integrations are reviewed as configuration.
- Adding an identity provider must not touch this package. One that needs a capability the spec cannot express is an engine change and needs a new audit.
- The spec is a public API, so it changes additively.

### The spec is data

- `IdentityProvider` and `OpenIDConnect` are frozen, slotted dataclasses without callables, imported from `homeassistant.components.auth`.
- `get_identity_provider(data, options)` is synchronous and receives the config entry data and options only, never `hass`, which makes I/O an obvious violation. The bridge calls it when an entry loads or changes, never while signing in or linking.
- `validate_identity_provider` checks exact types, so a `str` subclass is refused. It enforces an HTTPS issuer with a host and without credentials or a fragment, and `openid` among the scopes. Values out of bounds are rejected, not clamped.
- Registration builds the protocol client before anything is stored, so a spec the client refuses fails with `invalid_spec` instead of at the first sign-in.
- `async_validate_identity_provider` runs the same checks and fetches the discovery document, so a config flow rejects a spec before creating the entry. Every failure carries a stable `IdentityProviderError.reason`.
- Only built-in integrations may provide sign-in configuration. The bridge ignores the platform of a custom integration, so only reviewed code decides who signs in.

### Root and child providers

- The root provider `(oidc, None)` is enabled by default in `core_config.py`; a custom `auth_providers` list needs `- type: oidc`. It is never offered on the login screen.
- Every identity provider config entry is a child provider `(oidc, <entry_id>)`, resolved through `AuthProvider.child_providers` and `async_get_child_provider`. There is no general registration API, so integrations cannot inject provider code.
- The root stores a registry of identity providers (entry ID, domain and trust key) and creates a dormant child for each at startup. HTTP serves requests before config entries are set up, and existing tokens have to resolve and validate before, or without, the integration loading.
- A dormant child starts no sign-in or link flow and does not count as a login method.
- Names and icons are not stored. A child is named after its config entry title, passed in at runtime, and `/auth/providers` reports its `domain` so the frontend can show the brand icon.

### Linking only

An identity provider is another way to sign in to an existing Home Assistant user, like a password or a passkey. It never creates users.

- Only a signed-in user that is not system generated can start a link flow, and the resulting code only links to that user.
- Signing in with an identity that is not linked aborts `user_not_allowed`, and `/auth/token` answers 403 as a backstop.
- The external refresh token is revoked straight away and nothing is stored, so there is nothing to revalidate.
- Home Assistant multi-factor authentication applies after the external sign-in.

### Identity and account mapping

- A credential is keyed by the issuer and `sub`. Per OIDC Core 5.7 a subject is only unique within an issuer, so binding both stops a repointed identity provider inheriting existing accounts.
- The subject claim is not configurable: another signed claim may be reassignable, turning reassignment into account takeover.
- Nothing else is an identifier. 5.7 states that `preferred_username` is neither unique nor stable, which would make it a takeover vector.
- `account_name` is shown to the user next to the linked identity and refreshed at every sign-in. It is never used for matching.
- Linking compares nothing: whatever identity authenticates at the provider is attached to the signed-in account, and the Home Assistant display name is left alone.
- `config/auth_provider/oidc/unlink` detaches one of the caller's own identities. It is not admin-only, since linking is self-service too.
- Unlinking refuses unless the account keeps a login it can still use, which is `AuthManager.async_has_other_login_method`, not a rule of this provider's own. A credential of a dormant or removed provider does not count.

### Lifecycle

The bridge follows config entries of every domain with an `identity_provider` platform through `SIGNAL_CONFIG_ENTRY_CHANGED`, so integrations need no listener code and their setup is a no-op.

| Entry state | Login button | New sign-in or link | Existing sessions | Links |
| --- | --- | --- | --- | --- |
| Loaded, spec accepted | shown | yes | valid | kept |
| Not loaded yet, failed, or integration missing | hidden | no | valid | kept |
| Spec rejected | hidden | no | as not loaded, plus a repair issue | kept |
| Disabled | hidden | no | ended | kept |
| Trust key changed | shown | yes | ended | kept |
| Removed | gone | no | ended | removed, plus a repair issue naming users left without a login |
| Engine missing from `auth_providers` | – | – | – | config flows abort, existing entries get a repair issue |

- The trust key is a digest of the client ID, client secret, issuer and scopes. The account name claim only labels an identity, so it is left out and changing it keeps sessions. Rotating the client secret does end them.
- Ending the sessions of an identity provider removes every Home Assistant refresh token of its credentials, through the same path an ordinary revocation takes, so open connections close with it.
- Flows capture the configuration generation when they start and abort `configuration_changed` when it moved before they finish. Suspending bumps the generation too.
- Removal suspends the child first, so logins in flight abort, then collects the users left without another login, ends the sessions, removes the credentials and drops the registry record. After startup, registry records without a config entry are removed the same way.
- An authorization code is refused once its provider is gone. A refresh token used for the first time while its child is suspended or dormant is refused as well, so a code minted before the suspension cannot start a session. Tokens that were already used keep working while the integration loads.

### Binding a login to its browser

- `state` is a JWT signed with a per-process secret, expiring in five minutes. A restart only invalidates in-flight logins. `nonce` and `code_verifier` never leave the server.
- A signed state only proves a flow existed, so the flow is also bound to its browser by a cookie named per flow ID, required by both the callback and the final post. Without it, a delivered callback URL could sign a victim into an account they never authenticated as.
- Per-flow cookie names keep simultaneous logins independent, and keeping the cookie through the final post stops another browser on the same IP finishing the flow.
- That cookie is `HttpOnly`, scoped to `/auth`, and `SameSite=Lax`; `Strict` would strip it from the identity provider's cross-site top-level navigation.
- Home Assistant authorization codes are bound to their purpose: a `/auth/link_user` code cannot be exchanged at `/auth/token`, and a wrong-endpoint attempt does not consume it. Starting a link flow needs the user's bearer token from an interactive session inside its step-up window, and its code only links to that user. Unlinking needs the same. A long-lived access token cannot start a link flow. Unused codes expire after ten minutes, and revoking every session of a credential drops its unredeemed codes with them.

### Transport, tokens and storage

- Every endpoint must be HTTPS, including `revocation_endpoint` from discovery, which carries refresh tokens.
- No outbound request follows redirects: a redirect defeats the HTTPS check, and a 307 or 308 from the token endpoint would replay the client secret.
- The browser flow itself must be HTTPS unless the request arrived over the internal URL, since the tokens it carries are as exposed as the ones on the back channel.
- The discovery document is read from the issuer's well-known path, and its issuer must match the configured issuer exactly. A trailing slash is part of the identifier, so accepting either spelling would weaken issuer binding.
- PKCE is always `S256`. A provider advertising challenge methods without it is refused rather than downgraded to `plain`.
- Token responses must be labelled `Bearer`, compared case insensitively. A 200 without a bearer access token is a failure too, because some providers answer errors with 200.
- ID token algorithms are an allowlist intersected with what the provider advertises; `none` and the HMAC family are never accepted.
- A key is only used when the provider publishes it for verifying signatures, and a key that declares an algorithm is held to it.
- `iss`, `aud`, `azp`, `nonce`, `exp` and `iat` are verified with a small clock-skew leeway. `at_hash` is verified when present; EdDSA is excluded because OIDC pins no hash for it.
- Client authentication prefers `client_secret_basic` (the RFC 6749 default), falling back to `client_secret_post` only when advertised. Explicitly unsupported methods fail before the secret is sent.
- Unknown key IDs trigger a JWKS refetch behind a cooldown, so a forged `kid` cannot hammer the provider.
- The store uses `private=True` and atomic writes. It only holds the identity provider registry, never client secrets; those live in config entries. Unreadable records are discarded.

## How it works

### Integrations

- Config flows subclass `IdentityProviderConfigFlow` from the `auth` component and declare their forms, title and spec builder. The base aborts when the engine is not in `auth_providers` or no URL is available, shows the redirect URIs to register, validates every spec with `async_validate_identity_provider` before creating or updating an entry and maps validation reasons to the shared form errors. An integration that derives the entry from the input, such as through discovery with `async_discover_identity_provider`, overrides `async_resolve_setup` only.
- Reconfiguring never shows the stored client secret and always asks for it again; an empty secret turns the entry into a public client.
- Tests snapshot the spec for representative entries and run a sign-in and a link through the real engine against the fake identity provider in `tests/components/auth/common.py`.
- `config/auth_provider/oidc/list` returns the active identity providers and the caller's linked identities, including those of dormant providers marked unavailable. `config/auth_provider/oidc/unlink` detaches one of them.
- The login buttons, the linked accounts in the profile and translated abort reasons live in the frontend repository.

### Login flow

- Authorization code flow with PKCE `S256`, with or without a client secret.
- The browser leaves Home Assistant and returns to `/auth/login_callback`, the shared callback the `auth` component registers for any login flow with an external step. The callback validates state, flow existence, browser, IP and the relying client's redirect URI, then redirects to `/auth/authorize?flow_id=...&auth_callback=1` for a final frontend post.
- `EXTERNAL_STEP` may only move to another external step or to `EXTERNAL_STEP_DONE`; aborting raises `ValueError`. So `async_step_authorize` records failures and `async_step_finish` reports them.
- `EXTERNAL_STEP_DONE` needs a second `async_configure` call to reach `CREATE_ENTRY`; that is the final frontend post.

## Known gaps

- Identity providers can only link; creating users from an identity provider is a later step.
- The last-usable-login check is per provider. Two removals running concurrently in different providers can each count the other as the fallback.
- Step up authentication is not offered. Proving an identity again means a full browser redirect to the identity provider, so `support_step_up` stays off and a sensitive action has to be confirmed with another provider the account is linked to.
- A sign-in code minted just before a trust key change that keeps the child active can still be exchanged within its ten minutes.
- A link code minted before its identity provider was suspended can still be redeemed. The linked identity cannot sign in until the provider is active again.
- Login buttons only appear once the identity provider integrations are loaded. Existing sessions keep working in the meantime.
- The repair issue naming users left without a login after a removal stays until it is dismissed.
