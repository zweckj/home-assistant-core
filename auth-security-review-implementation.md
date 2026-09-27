---
title: Authentication Security Review Implementation Guide
description: Findings, evidence commands, remediation constraints, and regression scenarios for an agent re-reviewing or fixing the WebAuthn, restore-keys, and OIDC branches
ms.date: 2026-09-23
---

## Scope and Execution Rules

Review date: 2026-09-23. Threat model: internet-exposed Home Assistant, privileged accounts, revoked credentials, compromised existing sessions, and a malicious or compromised server or website that shares a relying party with the victim's instance.

Pinned targets. Read them with `git show <sha>:<path>`; every line number in this guide refers to these objects.

| Branch                                 | Tip            | Previous review tip |
|----------------------------------------|----------------|---------------------|
| `authentication/webauthn`              | `3c6b43a7a037` | `48db50f90a67`      |
| `authentication/webauthn-restore-keys` | `dd1871a2b85c` | not reviewed before |
| `authentication/oidc`                  | `c062441f1cde` | `2087c7201aa2`      |

* All three share merge base `dfb49d1d4666` with local `dev`. Shared layers: `auth/provider-lifecycle` (both providers), `auth/browser-origin` (WebAuthn), and `auth/external-step` (OIDC).
* `authentication/webauthn-restore-keys` is three commits on top of the WebAuthn tip (`409db000545`, `bfed74841b3`, `dd1871a2b85`). It is the branch checked out in the shared working tree.
* This review supersedes the 2026-09-06 review on `auth/review` (`aeea5b4cc46`). H1 to H3, M1, M2, and L1 to L3 are carried-forward tracking IDs; the letter reflects the severity when first filed, not the current rating. New IDs: H4, M3, L4.
* Do not switch branches in the shared checkout. Read pinned objects, or create a separate worktree when implementing. Do not run OIDC tests against the WebAuthn checkout and present the result as OIDC validation.
* Owner decisions that constrain remediation: M1 (the IdP owns initial-login MFA) is accepted design, so do not add HA MFA, mandatory `acr`/`amr`, or recent-authentication gates. Step-up authentication is out of scope, including the hooks on these tips; it appears only under [Out-of-Scope Observations](#out-of-scope-observations).
* Verification method: source review of the full diffs against `dev` and of the deltas since the previous tips, plus in-memory probes. WebAuthn probes used a real P-256 software authenticator with the installed `webauthn` 3.0.0 library and called the real login flow manager, `LoginFlowResourceView._async_flow_result_to_response`, and `TokenView.post` with mocked requests. OIDC probes loaded the pinned `homeassistant/auth` and `homeassistant/components` code over core modules that are identical between the branches, with mocked storage and IdP network. PyJWT 2.13.0 source was checked for key-binding behavior.
* Not exercised: repository test suites, a live HTTP server, a browser, a real authenticator, a real IdP, and the frontend.

## Priority and Severity

Request changes for H3, obtain an owner decision on H1, and add the M3 binding before any linking UI ships. Keep restore-key login and step-up unwired until H4 is resolved. No critical unauthenticated takeover was demonstrated on the reviewed tips.

| ID  | Branch          | Severity              | Status                             | Summary                                                                                      |
|-----|-----------------|-----------------------|------------------------------------|----------------------------------------------------------------------------------------------|
| H4  | restore-keys    | High (latent)         | New                                | The shared `my.home-assistant.io` relying party lets assertions be relayed between instances |
| H3  | WebAuthn        | Medium                | Open, unchanged                    | Passkey deletion leaves pending codes and in-flight logins redeemable                        |
| H1  | OIDC            | Medium (conditional)  | Open, unchanged                    | An admin grant survives refreshes that omit `groups` or the ID token                         |
| M3  | OIDC and shared | Medium (conditional)  | New                                | Link codes are not bound to the user who started linking                                     |
| H2  | OIDC            | Low (was Medium)      | Open, unchanged                    | Late ID-token verification re-promotes and reinserts an expired session                      |
| L4  | OIDC            | Low                   | New, present since `2087c7201aa2`  | Removal and config replacement wait behind the refresh worker's network calls                |
| L2  | WebAuthn        | Low                   | Partial; regressed on restore-keys | The last-passkey guard counts keys that cannot sign in                                       |
| L1  | WebAuthn        | Closed                | Fixed in code, tests partial       | Credential-ID uniqueness                                                                     |
| L3  | OIDC            | Closed with exception | Unchanged                          | External-URL HTTPS rule; internal HTTP is decided by `Host`                                  |
| M2  | OIDC            | Closed                | Fixed for declared restrictions    | JWK purpose and algorithm binding                                                            |
| M1  | OIDC            | Accepted              | Accepted design                    | The IdP owns initial-login MFA                                                               |

## H4 Shared Restore Relying Party

Severity: High, latent. Branch: `authentication/webauthn-restore-keys` only. Confidence: 7/10. Status: new. It is not reachable end to end, because nothing on this branch sets the restore flag on a login flow or step-up context.

### Evidence

```sh
git show dd1871a2b85c:homeassistant/auth/providers/webauthn.py | nl -ba | sed -n '72,75p;367,378p;570,616p;726,762p'
git show dd1871a2b85c:homeassistant/components/config/auth_provider_webauthn.py | nl -ba | sed -n '72,145p'
git show dd1871a2b85c:homeassistant/auth/models.py | nl -ba | sed -n '29,38p'
git diff 3c6b43a7a037 dd1871a2b85c --stat
```

* `RESTORE_RP_ID` is the constant `my.home-assistant.io`, and `RESTORE_ORIGINS` is `["https://my.home-assistant.io"]`, for every installation (lines 72 to 75).
* `_async_ceremony_relying_party()` returns that fixed relying party whenever `restore` is true and ignores the request origin. The `is_hass_url` allow-list used for browser ceremonies never runs (lines 367 to 378).
* `WebAuthnLoginFlow.async_step_init()` reads `context["restore"]` and passes it to `async_verify_authentication()` (lines 728 to 746). `async_start_step_up()` and `async_verify_step_up()` do the same (lines 575 to 577 and 600 to 615).
* Any signed-in, non-system user can register a restore key. `register` and `register_verify` take `restore` from the client, and `register_verify` skips the origin requirement for it (WebSocket module lines 75, 98 to 101, 115, and 129 to 142).
* `AuthFlowContext.restore` exists (models lines 35 to 38), but `LoginFlowIndexView` never sets it and the flow schema rejects extra keys. That is why the path is latent.
* Probe: `_async_ceremony_relying_party("https://evil.example", True)` returned the fixed relying party, and a restore assertion over a challenge from `async_start_authentication(None, True)` verified. Nothing in the signed data identifies the instance.

### Impact and Limits

* With a shared RP ID and origin, `rpIdHash` and `clientDataJSON.origin` are identical for every instance. The challenge is the only instance binding, and whichever server drives the ceremony chooses it.
* Relay sequence once wired: the attacker opens a restore login on victim instance B and receives challenge C_B. The victim's companion app, connected to attacker server A, is handed C_B; with an empty `allowCredentials` the OS lists every `my.home-assistant.io` passkey. The prompt looks the same for every instance, so the victim approves. A forwards the assertion to B, where challenge, origin, RP hash, signature, user verification, and counter (0 for synced passkeys) all pass. B issues a code and tokens without MFA, because `support_mfa` is false.
* Attacker preconditions: the victim's app signs in with a restore key to a server the attacker controls (lured, shared, family, or rental instance), or the attacker can run script on `https://my.home-assistant.io`. The latter makes that site a single point of compromise for every instance.
* Side effect: an instance that knows a victim's HA user ID can register a key with that user handle and overwrite the victim's restore key on the device (denial of service).
* Not demonstrated: an end-to-end relay through a companion app, since that wiring does not exist yet.

### Implementation Suggestions

1. Until assertions are bound to an instance, reject `restore=True` in `WebAuthnLoginFlow` and in `async_verify_step_up()`. Never make `restore` a client-selectable option on `/auth/login_flow`.
2. Bind the ceremony to the server the app actually connected to. For example, the server issues a nonce N, the app sends `challenge = SHA-256("ha-restore" || N || TLS-authenticated base URL)`, and the server recomputes it for each of its own `is_hass_url` URLs and accepts only on a match.
3. Prefer platform app origins, such as `android:apk-key-hash:`, over the shared website origin when validating app ceremonies.
4. Keep restore keys out of the last-login count until a supported login path can use them (see [L2](#l2-last-usable-login-policy)).

### Required Regression Scenarios

* An assertion bound to server A's URL over B's nonce is rejected by B with `invalid_auth`; one bound to B's URL succeeds.
* A client cannot set `restore` through `/auth/login_flow`, and a step-up context cannot enable it implicitly.
* Cross-mode rejection: a browser passkey presented under the restore RP fails, and a restore key presented to a browser ceremony fails.
* Restore registration, login, and step-up each get positive and negative tests; the delta currently has none.

## H3 Passkey Deletion Leaves Pending Logins Valid

Severity: Medium. Branch: `authentication/webauthn`; the same code is on restore-keys. Confidence: 9/10. Status: still open and unchanged since `48db50f90a67`. None of the delta commits touch this path.

### Evidence

```sh
git show 3c6b43a7a037:homeassistant/auth/providers/webauthn.py | nl -ba | sed -n '248,261p;488,536p;590,617p;697,719p'
git show 3c6b43a7a037:homeassistant/components/auth/__init__.py | nl -ba | sed -n '294,315p;467,492p'
git show 3c6b43a7a037:homeassistant/auth/__init__.py | nl -ba | sed -n '461,477p'
```

* `async_delete_credential()` deletes the key, revokes issued refresh tokens through `async_remove_refresh_tokens_for_credentials()`, and removes the shared `Credentials` only when no passkey remains (lines 590 to 617).
* `retrieve_result()` checks only purpose, one-time use, and the 10-minute lifetime (lines 467 to 492). `TokenView` then calls `async_get_or_create_user()` and `async_create_refresh_token(..., credential=credential)` (lines 294 to 315).
* In-flight logins: `async_update_user_registration()` silently does nothing when the key is gone (lines 256 to 261), and `async_verify_authentication()` still returns the user ID (lines 528 to 536). The flow finishes and a code is minted after revocation (lines 704 to 719).
* Probe H3a at this tip: a code from a passkey login was redeemed through `TokenView.post` after that passkey was deleted, returning 200 and a valid session.
* Probe H3b at this tip: the key was deleted while the verified login waited on its counter save. The flow still returned `create_entry`, and its code redeemed with 200.
* Fixed part: issued-token revocation now matches tokens by credential ID across all users, so it also works after the credentials are detached (`homeassistant/auth/__init__.py` lines 461 to 477; test at `tests/auth/test_init.py` lines 1564 to 1582).

### Impact and Limits

* Preconditions: the attacker can complete a passkey login (stolen, cloned, or synced key), holds an unredeemed code and renews it within the 10-minute lifetime, and the victim keeps at least one other passkey.
* The victim deletes the compromised key. The attacker's issued tokens die, but the held code yields a fresh refresh token with sliding expiry. This contradicts the in-code promise that every passkey session "has to go".
* Deleted keys cannot start new ceremonies. Long-lived access tokens carry no credential and survive deletion by existing design (see [Hardening Backlog](#hardening-backlog)).

### Implementation Suggestions

1. Purge pending codes on revocation. Have `async_remove_refresh_tokens_for_credentials()`, or a new shared hook, notify the auth component so it drops `temp_results` entries whose result ID matches. Alternatively, record a per-credential revocation time and reject codes created before it. Put this in the shared lifecycle so every provider inherits it.
2. Make `async_update_user_registration()` raise when the key is missing, and translate that into `InvalidAuthError` in `async_verify_authentication()`.
3. Keep provider-scoped cleanup and unrelated-provider sessions. Per-passkey session revocation is a larger model change and is not needed to close this gap.

### Required Regression Scenarios

* Log in with key A through the real flow and code store, keep the code, delete A while B remains, and POST the code to `/auth/token`. Require 400 and no new refresh token.
* Pause `_async_save` during a login, delete the key, and require `invalid_auth` from the flow.
* A fresh login with B still works, and unrelated-provider tokens stay valid.

## H1 Stale OIDC Admin Privileges

Severity: Medium, conditional on IdP claim behavior. Branch: `authentication/oidc`. Confidence: 8/10. Status: still open. The code is unchanged since `2087c7201aa2`; only the line numbers moved.

### Evidence

```sh
git show c062441f1cde:homeassistant/auth/providers/oidc/__init__.py | nl -ba | sed -n '565,606p;608,633p'
git show c062441f1cde:homeassistant/auth/providers/oidc/README.md | nl -ba | sed -n '63,68p'
git show c062441f1cde:tests/auth/providers/test_oidc.py | nl -ba | sed -n '2291,2330p'
```

* Groups are applied only when the refresh returns an ID token (line 576), and `_async_apply_refreshed_groups()` returns early when `groups` is absent (lines 622 and 623). Both paths still reach `mark_validated()` (lines 604 and 605).
* README line 66 leaves the grant "for the next interactive login", but sliding HA refresh tokens mean that login never has to happen. `test_revalidation_without_group_claims_leaves_admin_alone` (test line 2291) locks the retention in.
* Still working: explicit `groups` promotes and demotes, and `admin_group` is part of `trust_key`, so changing it ends all sessions.

### Impact and Limits

* A user removed from the IdP admin group stays an HA admin indefinitely through silent refreshes, provided the account stays active and refresh responses omit `groups` or the ID token.
* This is unknown entitlement, not forged claims. Upstream `invalid_grant`, explicit group removal, local demotion, and unlinking remain mitigations.
* OIDC permits refresh without an ID token, so requiring one on every refresh is an interoperability change rather than the only fix.

### Implementation Suggestions

1. Obtain an explicit owner decision on how long a provider-derived admin grant may live without authoritative reconfirmation. Documenting indefinite retention is not acceptance.
2. If the grant is bounded, track authorization freshness separately from session validity. For example, add an `authz_confirmed_at` field to `OidcSession`, set at login and whenever a refreshed ID token carries `groups`.
3. After a successful refresh, if the admin grant is older than the bound, withdraw the provider-derived admin with `_async_apply_admin_grant(..., granted_by_provider=True, grants_admin=False)`, or end the session to force an interactive login. Do not add step-up.
4. Preserve the omitted-versus-empty distinction, the owner exception, independently appointed local admins, and the `trust_key` teardown.

### Required Regression Scenarios

* Run repeated successful refreshes past the bound, once with an ID token lacking `groups` and once without an ID token. Require that the provider-derived admin is withdrawn or the session ends, and that admin is kept inside the window.
* Keep the explicit empty-group, role-addition, owner, and local-admin tests. Narrow `test_revalidation_without_group_claims_leaves_admin_alone` to the in-window case.

## M3 OIDC Link Codes Are Not Bound to the Initiator

Severity: Medium, conditional on the frontend; High if any frontend page redeems a `code` from its URL. Branch: `authentication/oidc`, through the shared `/auth/link_user` endpoint. Confidence: 6/10; the backend gap is verified, but exploitability depends on frontend behavior that was not reviewed. Status: new. The previous review listed link-code purpose separation as a preserved control but did not assess initiator binding.

### Evidence

```sh
git show c062441f1cde:homeassistant/components/auth/login_flow.py | nl -ba | sed -n '349,376p;582,589p'
git show c062441f1cde:homeassistant/components/auth/__init__.py | nl -ba | sed -n '420,452p'
git show c062441f1cde:homeassistant/auth/providers/oidc/__init__.py | nl -ba | sed -n '799,809p'
git show c062441f1cde:homeassistant/auth/providers/oidc/README.md | nl -ba | sed -n '35,37p'
```

* `POST /auth/login_flow` needs no session, and `link_user` is set from the client's `type` field (`login_flow.py` lines 357 and 375).
* The OIDC flow lets a new, unlinked identity through when `link_user` is set, even with `allow_auto_create` off (`oidc/__init__.py` lines 803 to 809; README line 35).
* `LinkUserView` attaches the code's credentials to whichever user presents the bearer token (`components/auth/__init__.py` lines 430 to 451). The code is bound only to its purpose and to a `client_id` that the initiator chooses. No initiating user or browser is recorded.
* After the IdP detour, the callback redirects to `/auth/authorize` with only `flow_id`, `client_id`, `redirect_uri`, and `auth_callback` (lines 582 to 589). The OAuth client's original `state` is not carried across, which weakens any client-side check that a returned code belongs to a flow the client started.

### Impact and Limits

* Attack, if a frontend page redeems a URL code: the attacker signs in at the configured IdP with an unlinked identity, starts a `type=link_user` flow with the victim's frontend as `client_id`, and completes it. The attacker then sends the victim a crafted link carrying the code. The victim's signed-in frontend redeems it and attaches the attacker's identity to the victim's account, including admin accounts. The attacker can then sign in as the victim through OIDC.
* Limits: `/auth/link_user` requires a bearer token and signed paths only allow GET and HEAD, so a plain cross-site request cannot redeem the code. Codes expire after 10 minutes. With a private IdP, the attacker needs an account there.

### Implementation Suggestions

1. Require an authenticated user to start `type=link_user` flows, store that user's ID with the code, and have `LinkUserView` reject a mismatch.
2. Additionally, bind link codes to the initiating browser (for example, with the browser token used for the external step) and carry the client's OAuth `state` across the IdP detour.
3. Confirm the frontend never redeems a `code` query parameter at `/auth/link_user` without a local state check.

### Required Regression Scenarios

* A link code minted by an unauthenticated or different initiator is rejected at `/auth/link_user` for another user, and no credential is attached.
* The initiator can still link their own identity, and the purpose-separation tests stay.
* In the frontend repository, a crafted link carrying a foreign code links nothing.

## H2 Late OIDC Verification Restores Expired Sessions

Severity: Low, previously Medium. Branch: `authentication/oidc`. Confidence: 9/10. Status: still open and reproduced again. The code is unchanged.

### Evidence

```sh
git show c062441f1cde:homeassistant/auth/providers/oidc/__init__.py | nl -ba | sed -n '498,548p;565,606p;622,633p'
git show c062441f1cde:homeassistant/auth/providers/oidc/store.py | nl -ba | sed -n '258,262p'
git show c062441f1cde:homeassistant/auth/providers/oidc/README.md | nl -ba | sed -n '63,65p'
```

* `_async_expire_sessions()` runs outside `_revalidate_lock` (line 505). It can end the session while the worker awaits `async_verify_id_token()` (lines 577 to 579).
* The current-session checks sit at line 571, before verification, and line 599, after the role change. Nothing re-checks between verification and `_async_apply_admin_grant()` plus `data.async_set_session(session)` (lines 626 to 633).
* `async_set_session()` always inserts (store lines 258 to 262). A reinserted object passes the check at line 599 and gets a new deadline at lines 604 and 605. The rotated-token write at line 575 cannot reinsert, since nothing suspends between lines 571 and 575.

Probe variants at this tip. In every case, expiry first demoted the user and removed the session.

| Variant | Initial grant | Late claims  | Result after release                             | New token for the credential |
|---------|---------------|--------------|--------------------------------------------------|------------------------------|
| A       | Non-admin     | Admin group  | Promoted; session reinserted with a new deadline | Accepted                     |
| B       | Admin         | Admin group  | Re-promoted; session not reinserted              | Rejected                     |
| C       | Admin         | `groups: []` | Stays non-admin; session reinserted              | Accepted                     |
| D       | Admin         | No `groups`  | No change                                        | Rejected                     |

### Impact and Limits

* The expiry-driven demotion is reversed and usable through any other login the user holds. A reinserted session keeps refreshing, so a code issued within the last 10 minutes becomes redeemable again. This contradicts README line 64 ("cannot hold a session open past it").
* The restored grant matches claims the IdP signed moments earlier, and the old HA tokens stay revoked. It is a lifecycle consistency defect rather than an escalation beyond what the IdP asserts, which is why it is now rated Low. Explicit removals serialize on `_revalidate_lock` and are covered by [L4](#l4-oidc-removal-waits-behind-the-refresh-worker) instead.

### Implementation Suggestions

1. Add `if not self._async_session_is_current(data, session): return False` immediately after line 579, before the subject check and any group handling.
2. In `_async_apply_refreshed_groups()`, update the stored session only while it is still current and never insert a missing one. Use a compare-and-update helper instead of `async_set_session()` on refresh paths.
3. Keep expiry outside the network-held lock, and keep rotating-token handling, the owner and local-admin exceptions, and the revocation callbacks.

### Required Regression Scenarios

* Parameterize variants A to D: block `async_verify_id_token`, move `revalidate_after` into the past, run `_async_expire_sessions()`, then release. Require session absence, non-admin status, rejection of new tokens for the credential, and a still-valid non-OIDC token.
* Keep `test_expiry_is_not_delayed_by_a_slow_identity_provider` (test line 2444) and the slow-token-request controls.

## L4 OIDC Removal Waits Behind the Refresh Worker

Severity: Low. Branch: `authentication/oidc`. Confidence: 9/10. Status: new, and already present at `2087c7201aa2`.

### Evidence

```sh
git show c062441f1cde:homeassistant/auth/providers/oidc/__init__.py | nl -ba | sed -n '203,219p;333,345p;509,528p'
git show c062441f1cde:homeassistant/auth/providers/oidc/README.md | nl -ba | sed -n '71p'
git show c062441f1cde:tests/auth/providers/test_oidc.py | nl -ba | sed -n '2055,2100p'
```

* The worker holds `_revalidate_lock` for the whole pass, including every token request and ID-token verification (lines 513 to 528). Each request can run until the client timeout, and due sessions stay due while the IdP keeps failing.
* `_async_remove_credentials_session()` takes `self._config_lock` and `self._revalidate_lock` (line 335), and replacing or deleting the config takes `_revalidate_lock` (line 203). User removal goes through the credential path.
* README line 71 claims "network delay cannot postpone unlinking". Probe: with a refresh blocked, `hass.auth.async_remove_user()` had not finished after 0.5 s. The user still existed, their OIDC-bound token still minted access tokens, and their non-OIDC token stayed valid until the refresh was released.
* `test_revalidation_cannot_restore_removed_credentials` (test line 2055) checks only the end state.

### Impact and Limits

* Deleting a compromised user, unlinking, or deleting the OIDC config as an emergency stop is delayed by up to one worker pass behind a slow or blackholed IdP. The delay grows with the number of due sessions.
* Deactivating the user is not delayed and remains a stopgap.

### Implementation Suggestions

1. Stop holding `_revalidate_lock` across network I/O. Mark due sessions as in flight under the lock, release it for the requests, and retake it briefly to commit results through the current-session check.
2. Land the H2 fix first, since releasing the lock widens the window H2 describes.
3. Correct README line 71, or make it true.

### Required Regression Scenarios

* Block `async_refresh_token`, then run `async_remove_user`, `async_remove_credentials`, and `async_set_config(None)` under `asyncio.wait_for(..., 1)`. Require completion and token revocation, then release the refresh and require that nothing is restored.

## L2 Last Usable Login Policy

Severity: Low; a self-lockout, not a bypass. Status: fixed on the OIDC side, partial on WebAuthn, and regressed on restore-keys.

### Evidence

```sh
git show 3c6b43a7a037:homeassistant/auth/__init__.py | nl -ba | sed -n '438,459p'
git show 3c6b43a7a037:homeassistant/auth/providers/__init__.py | nl -ba | sed -n '141,144p'
git show 3c6b43a7a037:homeassistant/auth/providers/webauthn.py | nl -ba | sed -n '590,603p'
git show dd1871a2b85c:homeassistant/auth/providers/webauthn.py | nl -ba | sed -n '274,286p;624,634p'
git show c062441f1cde:homeassistant/auth/providers/oidc/__init__.py | nl -ba | sed -n '269,276p'
```

* `async_has_other_login_method()` now asks each provider through `async_can_login_with_credentials()`. OIDC overrides it to require a configured provider and a matching issuer, with a `configuration-removed` test case (`tests/auth/providers/test_oidc.py` line 1587). This closes the previous unconfigured-provider concern.
* WebAuthn does not override the hook, and its guard counts every stored passkey, including keys for RP IDs that HA no longer serves (line 597). A user with one live and one stale key can delete the live one.
* On restore-keys, the guard uses `count_credentials()`, which counts restore keys for any RP (lines 284 to 286 and 631). Probe: a user with one browser passkey adds a restore key, deletes the browser passkey, and is left with no working login.
* Remaining, and not a bypass: the documented race between concurrent removals in different providers (OIDC README line 135), and the admin password-delete command in `auth_provider_homeassistant.py`, which still has no fallback check.

### Implementation Suggestions

1. Override `async_can_login_with_credentials()` in WebAuthn, and count only passkeys whose `rp_id` HA currently serves in the last-passkey guard. Exclude restore keys until a supported login path accepts them.
2. When combining the branches, test final-passkey deletion against an OIDC fallback that exists but is unconfigured.

### Required Regression Scenarios

* A user with one live and one stale-RP passkey cannot delete the live one without another login method.
* On restore-keys, a restore key does not satisfy the last-passkey guard.

## Closed and Accepted Items

* M1, IdP-owned initial-login MFA: accepted design, and `support_mfa` is false on both providers. Do not refile it or remediate it with HA MFA or step-up.
* M2, JWK purpose and algorithm binding: fixed for keys that declare `use`, `key_ops`, or `alg` (`client.py` lines 69 to 80, 542 to 545, and 614). PyJWT 2.13.0 rejects a header `alg` that differs from the key's declared one. Keys without `alg` still accept any advertised allowlisted asymmetric algorithm by design; per-client algorithm pinning remains optional hardening.
* L1, credential-ID uniqueness: fixed in code, with a server-wide check and no await before insertion (`webauthn.py` lines 212 to 224). Tests cover same-user duplicates only, so add a cross-user duplicate test that asserts the stored key and counter are unchanged.
* L3, OIDC browser transport: unchanged. External HTTP is refused, but the internal exception is decided by the `Host` header through `is_internal_request()` (`oidc/__init__.py` lines 251 to 255), and cookies use `secure=request.secure` (`login_flow.py` line 402). Enforce TLS and forwarded-header trust at the deployment boundary, and do not describe this as a transport guarantee.
* Delta commits since the previous tips introduced no vulnerability. Reviewed: revocation by credential ID (`74e60407b14`); credential-aware fallback checks (`1bd7497a398` and merges); OIDC profile enrichment separated from authorization claims (`55056629a22`); self-revoking WebSocket replies (`eb6e3feba1e` and merges); passkey-deletion acknowledgement (`04b00fac4ba`); missing-credential login handling (`95c4b059df6`); and explicit code purposes (`75106abde0f`).
* After `55056629a22`, admin comes only from verified ID-token claims. An IdP that sends `groups` only through UserInfo can no longer grant admin, which fails safe.
* After `75106abde0f`, a wrong-purpose redemption returns nothing and does not consume the code. Link codes cannot buy tokens, and login codes cannot link identities.
* Self-revoking WebSocket commands defer the close only for the revoking task. Other revocations close immediately, and incoming frames are dropped once revoked.
* Previous test gaps now closed: a real WebSocket connection closes on ordinary OIDC expiry (`tests/components/auth/test_login_flow.py` line 1011), and an admin command is refused on an open connection after demotion (line 967). WebAuthn management endpoints have broad coverage in `tests/components/config/test_auth_provider_webauthn.py`, including cross-user access and reply-before-close on self-deletion.

## Hardening Backlog

Defense-in-depth and lower-confidence items. W is `3c6b43a7a037`, R is `dd1871a2b85c`, and O is `c062441f1cde`.

| Area     | Location                                                                              | Issue                                                                                                                                                                                                                    | Suggested change                                                                                          |
|----------|---------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| WebAuthn | W `webauthn.py` 493-496; W `auth_provider_webauthn.py` 114                            | A malformed `userHandle` raises `binascii.Error`, returning HTTP 500 without `process_wrong_login`                                                                                                                       | Catch `(WebAuthnException, ValueError)` and validate `credential` as `vol.Any(str, dict)`                 |
| WebAuthn | W `webauthn.py` 256-261                                                               | Backup eligibility is overwritten on every login                                                                                                                                                                         | Keep the registration-time BE flag and update only BS                                                     |
| WebAuthn | W `components/auth/__init__.py` 549-555                                               | Long-lived access tokens carry no credential and survive passkey deletion (existing design)                                                                                                                              | Tag them with the creating session's credential, or offer revoke-all on deletion                          |
| WebAuthn | W `auth_provider_webauthn.py` 115, 181                                                | Passkey names have no length limit                                                                                                                                                                                       | Use `vol.All(str, vol.Length(1, 64))`                                                                     |
| WebAuthn | W `webauthn.py` 365-367                                                               | `async_can_start_login` tells unauthenticated clients whether any passkey exists                                                                                                                                         | Accept and document, or always offer the provider                                                         |
| WebAuthn | W `webauthn.py` 525-526, 715-717                                                      | A counter regression, a possible clone, is logged only at debug level                                                                                                                                                    | Log a warning and flag the key                                                                            |
| WebAuthn | W `auth_provider_webauthn.py`                                                         | Admins cannot list or revoke another user's passkeys                                                                                                                                                                     | Add admin commands for incident response                                                                  |
| WebAuthn | W `webauthn.py` 11-33; W `core_config.py` 365; W `providers/__init__.py` 217-245      | Availability: the provider is enabled by default and imports `webauthn` at module level, but the package is only in `requirements_all.txt`, and the module is imported before `REQUIREMENTS` are processed               | Import lazily as `totp.py` does, or make it a core dependency                                             |
| WebAuthn | W `webauthn.py` and `async_finish_flow`                                               | Passkey logins skip enrolled HA MFA, attestation is `none`, and UV is the authenticator's own claim                                                                                                                      | Document the trust model                                                                                  |
| Shared   | W `connection.py` 128-159                                                             | A self-revoked connection keeps existing subscriptions streaming for up to `AUTH_CLOSE_DELAY` (2 s); for OIDC update and delete, the window includes IdP revocation calls                                                | Unsubscribe everything except auth once `_auth_revoked` is set, or close as soon as the reply is written  |
| Shared   | O `oidc/__init__.py` 361-393, 622-633                                                 | Demotion does not revoke tokens; admin-only subscriptions opened earlier keep streaming (existing HA behavior, now triggered automatically)                                                                              | Close admin-only subscriptions on demotion                                                                |
| OIDC     | O `login_flow.py` 392-407, 456                                                        | The browser binding exists only when the first step is external                                                                                                                                                          | Reject POSTs while a flow awaits the callback, and set the token whenever a flow reaches an external step |
| OIDC     | O `login_flow.py` 396-407, 491                                                        | The cookie has no `__Host-` prefix and `Secure` follows `request.secure`; the flow ID is readable in the signed state, and DELETE on the flow needs no cookie                                                            | Use `__Host-`, always set `Secure` on HTTPS, and require the cookie for DELETE (denial of service only)   |
| OIDC     | O `store.py` 37-44, 85-89                                                             | A string `groups` claim is split on spaces, so `admin_group="admins"` matches `"not admins"`                                                                                                                             | Treat a string as one group name and update README line 50                                                |
| OIDC     | O `oidc/__init__.py` 521-528; O `client.py` 626                                       | One unexpected exception, such as a PyJWT `TypeError` for a key without `alg` of the wrong type, aborts a pass before collected sessions are ended                                                                       | Catch per session, end collected sessions in `finally`, and map PyJWT errors to `OidcIdTokenError`        |
| OIDC     | O `oidc/__init__.py` 194-201; O `components/auth/__init__.py` 540                     | Tightening settings does not reach existing sessions or codes: a lower `revalidate_interval` keeps old deadlines, and codes from the last 10 minutes can still auto-create users after `allow_auto_create` is turned off | Pull deadlines in, and end sessions of not-yet-linked credentials                                         |
| OIDC     | O `const.py` 21; O `store.py` 57-58                                                   | Admin mapping is on by default under the fixed group `home_assistant_admin`, and there is no admission filter for auto-created accounts (auto-create itself defaults to off)                                             | Make admin mapping opt-in, and add an allowed-groups or required-claim filter                             |
| OIDC     | O `client.py` 311                                                                     | The authorize request sends no `prompt` or `max_age`, so an active IdP session gives silent SSO to whichever IndieAuth client started the flow                                                                           | Consider `prompt` for third-party clients; confirm consent in the frontend                                |
| OIDC     | O `oidc/__init__.py` 822-829; O `login_flow.py` 305-331; O `oidc/__init__.py` 122-130 | A session saved for a not-yet-linked account lingers and keeps refreshing when no code is issued, until restart                                                                                                          | Prune on flow abort or code expiry                                                                        |
| OIDC     | O `oidc/__init__.py` 577-580; O `store.py` 100-111                                    | Refreshed ID tokens are not compared with the original nonce, `auth_time`, or audience (OIDC Core section 12.2)                                                                                                          | Store the originals and compare when returned                                                             |
| OIDC     | O `oidc/__init__.py` 580-589                                                          | Sessions ended for a subject mismatch or `invalid_grant` do not revoke the IdP refresh token                                                                                                                             | Revoke on a best-effort basis                                                                             |
| OIDC     | O `login_flow.py` 462-463, 551                                                        | `hmac.compare_digest` raises on a non-ASCII cookie, returning HTTP 500                                                                                                                                                   | Compare bytes, or catch the error                                                                         |
| OIDC     | O `login_flow.py`                                                                     | Login flows never expire on the server (existing behavior)                                                                                                                                                               | Add a flow lifetime (denial of service only)                                                              |
| OIDC     | O `README.md` 37, 42, 50, 64, 66, 71                                                  | Inaccurate claims: relinking after unlink, the nonce staying server-side, space-separated groups, the hard deadline (H2), grant retention (H1), and unlink timing (L4)                                                   | Correct the README alongside the fixes                                                                    |

## Verified Protections

Do not refile these without new evidence.

* WebAuthn challenges are 64 random bytes. A login challenge is per flow, the flow is bound to the client IP, the challenge is replaced after each attempt and expires after 60 s, and concurrent steps return 409 (W `login_flow.py` 410-420; W `webauthn.py` 700).
* WebAuthn registration challenges are popped under a lock and removed by a timer (W `webauthn.py` 411).
* WebAuthn origin and RP ID come only from the `Origin` header, which must be HTTPS, not an IP address, and pass `is_hass_url`. `Host` and `X-Forwarded-*` are not used, and a subdomain origin was rejected by probe (W `webauthn.py` 99-116).
* User presence is always required and user verification is required at registration and login. The counter must increase, `id` must equal `rawId`, and only EdDSA, ES256, and RS256 are accepted (W `webauthn.py` 424, 523; library source).
* Passkey lookup is scoped to the user handle and credential ID pair, and a swapped user handle was rejected by probe (W `webauthn.py` 509). Passkeys never create users (W `webauthn.py` 636-660).
* WebAuthn management commands act only on `connection.user`, system users cannot register, and the last-passkey check and deletion run without an intervening await (W `auth_provider_webauthn.py` 84; W `webauthn.py` 590-605).
* Inactive and local-only users are blocked at flow completion and at `/auth/token` (W `login_flow.py` 298; W `components/auth/__init__.py` 302-311). `invalid_auth` feeds `process_wrong_login`, error messages are uniform, and `allowCredentials` is empty at login.
* OIDC login `state` is HS256-signed with a 256-bit per-process secret, expires after 5 minutes, and requires `exp` and `flow_id` (O `auth/__init__.py` 127, 136-156).
* The OIDC callback checks, in order, that the flow awaits the callback, the IP matches, the per-flow HttpOnly SameSite=Lax cookie matches in constant time, the redirect URI verifies, and the flow still awaits after that await. The `Location` is a relative `/auth/authorize` URL built from stored values (O `login_flow.py` 516-567, 582-589).
* The OIDC final POST requires the same IP, `client_id`, and cookie, and allows one request per flow at a time (O `login_flow.py` 450-485).
* PKCE uses S256 with a `token_urlsafe(64)` verifier, and the nonce is 256 bits and checked at login (O `client.py` 117-123, 247, 638; O `oidc/__init__.py` 679-680, 784).
* ID tokens use an asymmetric-only allowlist and enforce declared key restrictions. `aud`, `iss`, `exp`, `iat`, and `nbf` are required with 30 s leeway, and `azp`, constant-time `at_hash`, and rate-limited JWKS refetch are in place (O `client.py` 534, 614-636, 675).
* Discovery requires an exact issuer match and HTTPS endpoints, redirects are never followed, TLS is verified, only `Bearer` tokens are accepted, and unsupported client-auth methods are refused before the secret is sent (O `client.py` 237, 407, 418-436).
* OIDC identity is keyed by verified issuer and subject, never by email or username, and the UserInfo `sub` must match exactly (O `oidc/__init__.py` 278-300, 800; O `client.py` 490-492).
* The owner is never demoted, and changing issuer, client, secret, scopes, or admin group ends all sessions (O `store.py` 62-76; O `oidc/__init__.py` 195-219).
* OIDC config commands require admin, `unlink` touches only the caller's credentials, the client secret is never returned, and stores are private, atomic, and type-checked on load (O `auth_provider_oidc.py` 145, 159, 190, 242, 281-294, 317; O `store.py` 122-172).

## Out-of-Scope Observations

Step-up is excluded by owner decision. These are recorded, not filed.

* The WebAuthn step-up challenge is keyed by user rather than session, so parallel sessions overwrite each other's challenge, and `async_start_step_up()` raises `InvalidAuthError` instead of `InvalidStepUpError` (W `webauthn.py` 545-573).
* On restore-keys, step-up honors `context["restore"]` (R `webauthn.py` 575-577, 600-615), so H4 applies to any step-up consumer that sets it.
* Passkey register, delete, and rename are not gated by re-verification (W `auth_provider_webauthn.py` 72-196). A stolen session can add a persistent passkey, comparable to creating a long-lived access token.
* OIDC does not offer step-up (README line 136). The shared step-up hooks are used only by `websocket_change_password`, which behaves like the previous `async_validate_login` call.

## Test Coverage Gaps

WebAuthn:

* Signed-ceremony negatives through the real endpoints: UV or UP of 0, wrong or subdomain origin, wrong RP hash, replayed or expired challenge, counter regression, swapped user handle, `id` different from `rawId`, and a valid zero-counter key. Every current test patches the verifier or `_async_relying_party`.
* Assertions on the arguments passed to `verify_authentication_response`, including user verification and expected origin.
* H3 code redemption after deletion and deletion during a login; the L1 cross-user duplicate; the L2 stale-RP and restore-key guard cases.
* Ban counting for failed assertions and for the malformed `userHandle` path, plus an HTTP-level `Origin` outside the allow-list.
* Restore-keys: registration, login, step-up, cross-mode rejection, the `count_credentials` lockout, and relay rejection (H4).

OIDC:

* H2 variants A to D, L4 removal under a blocked refresh, and the H1 freshness bound.
* The `code_verifier` sent to the token endpoint matches the `code_challenge`, and a flow-level nonce mismatch aborts with `invalid_id_token`.
* Cookie `Secure` (including behind `X-Forwarded-Proto`) and `SameSite` attributes.
* A `groups` string with multi-word names, and unexpected errors during refresh or login.
* M3 initiator binding, an external step after a form step, tightening settings while codes are outstanding, admin subscriptions after demotion, and refreshed-token nonce, `auth_time`, and audience consistency.
* End to end: real signed tokens through the callback, the final POST, and `/auth/token`. The current HTTP tests patch `async_exchange_code` and `async_verify_id_token` (O `tests/components/auth/test_login_flow.py` 824-890).

## Implementation and Verification Order

1. Reconfirm the tips with `git rev-parse` before implementing. If they moved, re-run the evidence commands and re-anchor line numbers.
2. Write failing tests first for H3 (code after deletion, deletion during login), H2 (variants A to D), and L4 (removal under a blocked refresh).
3. Fix H3 in the shared lifecycle with a code purge on revocation, plus the WebAuthn missing-key error. Fix H2 before L4, because releasing the lock widens the H2 window.
4. Resolve H1 with the owner, then implement the chosen bound.
5. Add M3 initiator binding in the shared auth component before any linking UI ships, and check the frontend.
6. On restore-keys, gate the restore paths (H4) and fix the L2 count before wiring companion-app login.
7. Add signed-ceremony WebAuthn tests and end-to-end OIDC tests.
8. Run focused tests per branch in its own worktree with `uv run --no-sync pytest`, then `uv run --no-sync prek run --all-files`.

## Completion Criteria

* H4: no restore assertion is accepted unless it is bound to the instance, `restore` is not client-selectable, and restore keys do not count as a login method until they are usable.
* H3: pre-deletion codes and in-flight logins cannot produce a session after deletion, and a fresh login with a remaining key works.
* H1: the owner decision is recorded; if bounded, missing claims cannot renew a provider-derived admin grant past the bound.
* M3: link codes are redeemable only by the initiating user or browser, and the frontend is verified.
* H2: a refresh that completes after expiry cannot change roles or reinsert the session.
* L4: removal and config replacement complete promptly while a refresh is blocked, and the README is accurate.
* L2: WebAuthn counts only usable passkeys.
* M1 stays unchanged, the closed M2, L1, and L3 controls stay covered, and step-up stays untouched.
