---
title: Authentication Security Review
description: Security re-review of the WebAuthn, WebAuthn restore-keys, and OIDC authentication branches
ms.date: 2026-09-23
---

## Open Findings

* [HIGH H4, latent, restore-keys only] Bind restore-key assertions to the instance before any login or step-up path accepts them. Every installation shares the relying party `my.home-assistant.io`, and the restore path skips the origin allow-list, so a malicious server the companion app connects to, or script running on that site, can relay a sign-in to the victim's instance. Nothing sets the restore flag yet; it becomes exploitable once companion-app login is wired up. [Details](auth-security-review-implementation.md#h4-shared-restore-relying-party).
* [MEDIUM H3] Invalidate pending login codes and in-flight logins when a passkey is deleted. Issued tokens are revoked, but a code obtained before deletion, or a login that completes during it, still produces a fresh session while another passkey remains. Reproduced again and unchanged since the last review. [Details](auth-security-review-implementation.md#h3-passkey-deletion-leaves-pending-logins-valid).
* [MEDIUM H1, conditional] Bound how long an IdP-derived admin grant survives refreshes without `groups`. Explicit group changes work, but refreshes that omit the claim or the ID token keep admin indefinitely. The README documents this, but the owner has not accepted it as policy. [Details](auth-security-review-implementation.md#h1-stale-oidc-admin-privileges).
* [MEDIUM M3, new, conditional] Tie `/auth/link_user` codes to the user who started linking. Anyone who can sign in at the IdP can start a link flow without an HA session, and whoever redeems the code gets that identity attached. If any frontend page redeems a `code` from its URL, this becomes account takeover. The frontend was not reviewed. [Details](auth-security-review-implementation.md#m3-oidc-link-codes-are-not-bound-to-the-initiator).
* [LOW H2, downgraded] Re-check the session immediately after refreshed ID-token verification. A verification that finishes after expiry still re-promotes the user and can reinsert the session. The claims are fresh and IdP-signed, so this breaks the documented hard deadline rather than escalating privileges. [Details](auth-security-review-implementation.md#h2-late-oidc-verification-restores-expired-sessions).
* [LOW L4, new] Stop holding the OIDC refresh lock across network calls. Removing a user, unlinking, or deleting the OIDC config waits behind a slow IdP while tokens stay valid, contrary to the README. Deactivating the user still takes effect immediately. [Details](auth-security-review-implementation.md#l4-oidc-removal-waits-behind-the-refresh-worker).
* [LOW L2, WebAuthn] Count only passkeys that can still sign in. The last-passkey guard counts keys for relying party IDs HA no longer serves, and on restore-keys it also counts restore keys, so a user can delete their last working passkey. [Details](auth-security-review-implementation.md#l2-last-usable-login-policy).

## Re-Review Status

* Fixed since 2026-09-06: an unconfigured OIDC provider no longer counts as a fallback login, token revocation no longer depends on the credential still being linked, and authorization codes carry an explicit purpose. JWK restrictions (M2), duplicate passkey IDs (L1), and the external-URL HTTPS rule (L3) remain in place. [Status](auth-security-review-implementation.md#closed-and-accepted-items).
* None of the commits since the last review introduced a vulnerability. Self-revoking WebSocket commands reply before closing; the 2-second window in which subscriptions keep streaming is hardening.
* [TEST GAP] WebAuthn tests still mock the verifier, so signed-ceremony negatives are missing, and restore keys have no tests. OIDC lacks tests for the expiry race, the removal delay, and real signed tokens through the callback and `/auth/token`. [Gaps](auth-security-review-implementation.md#test-coverage-gaps).
* [AVAILABILITY] The passkey provider is enabled by default and imports `webauthn` at module level, but the package is only listed in `requirements_all.txt`. On installs without it, auth setup fails before requirements are installed.
* M1 (IdP-owned MFA) remains accepted. Step-up remains out of scope; observations are recorded separately. [Details](auth-security-review-implementation.md#out-of-scope-observations).

## Assessment

Request changes before internet-facing deployment: fix H3, decide H1, and add the M3 binding before a linking UI ships. Keep restore-key login and step-up disabled until H4 is resolved. No critical unauthenticated takeover was demonstrated on the reviewed tips.

Reviewed WebAuthn `3c6b43a7a037`, restore-keys `dd1871a2b85c`, and OIDC `c062441f1cde` against merge base `dfb49d1d4666`, without switching branches. Findings come from source review plus in-memory probes (a real P-256 software authenticator for WebAuthn, with storage and IdP network mocked). No repository test suites, browser, real authenticator, or real IdP were run.
