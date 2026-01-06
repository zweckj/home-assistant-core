# WebAuthn Authentication Provider for Home Assistant

This authentication provider implements FIDO2/WebAuthn passwordless authentication for Home Assistant.

## Overview

The WebAuthn provider uses hardware security keys, platform authenticators (like Windows Hello, Touch ID, or Android biometrics), or other FIDO2-compliant authenticators for secure, passwordless login.

## Features

- **Passwordless Authentication**: No passwords to remember or store
- **Hardware-backed Security**: Uses cryptographic keys stored in authenticators
- **Phishing Resistant**: Credentials are bound to your domain
- **Multi-device Support**: Register multiple authenticators per user

## Configuration

Add the WebAuthn provider to your `configuration.yaml`:

```yaml
homeassistant:
  auth_providers:
    - type: webauthn
```

## Usage

### Registration

To register a new authenticator:

1. Users must first be created in Home Assistant
2. The registration flow generates options using the `webauthn` library
3. The browser's WebAuthn API (`navigator.credentials.create()`) is called
4. The authenticator's public key is stored securely

### Authentication

To authenticate:

1. User provides their username
2. A challenge is generated server-side
3. The browser's WebAuthn API (`navigator.credentials.get()`) is called
4. The authenticator signs the challenge with its private key
5. The server verifies the signature using the stored public key

## Requirements

- Python package: `webauthn==2.3.0` (automatically installed)
- HTTPS connection (required by WebAuthn specification)
- Browser with WebAuthn support (modern browsers)
- FIDO2-compatible authenticator

## Security Considerations

- Challenges are randomly generated and stored temporarily
- Public keys are stored securely in Home Assistant's auth storage
- Sign counters are tracked to detect cloned authenticators
- All cryptographic operations follow FIDO2/WebAuthn standards

## Implementation Notes

This provider implements the server-side WebAuthn logic. Full integration requires:

1. Frontend JavaScript to interact with `navigator.credentials` API
2. Proper configuration of RP ID (Relying Party ID) based on your domain
3. HTTPS for security (WebAuthn requirement)

## Testing

Run tests with:

```bash
pytest tests/auth/providers/test_webauthn.py
```

## References

- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [FIDO Alliance](https://fidoalliance.org/)
- [Python webauthn library](https://pypi.org/project/webauthn/)
- [Home Assistant Auth Provider Documentation](https://developers.home-assistant.io/docs/auth_auth_provider/)
