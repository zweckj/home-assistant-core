"""Tests for hassfest identity_provider."""

from pathlib import Path

import pytest

from script.hassfest import identity_provider
from script.hassfest.model import Config, Integration

VALID_IDENTITY_PROVIDER = """
from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import IdentityProvider


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    return IdentityProvider()
"""


def _config(root: Path) -> Config:
    """Return a config for a synthetic core tree."""
    return Config(
        root=root,
        specific_integrations=None,
        action="validate",
        requirements=True,
    )


def _create_integration(
    root: Path,
    domain: str,
    *,
    manifest_extra: dict | None = None,
    identity_provider_content: str | None = VALID_IDENTITY_PROVIDER,
    config: Config | None = None,
) -> Integration:
    """Create a synthetic integration."""
    config = config or _config(root)
    integration_path = root / "homeassistant/components" / domain
    integration_path.mkdir(parents=True)
    manifest = {
        "domain": domain,
        "name": domain,
        "documentation": "https://example.com",
        "codeowners": ["@awesome"],
        "dependencies": ["auth"],
        "config_flow": True,
        "integration_type": "service",
    }
    if manifest_extra:
        manifest.update(manifest_extra)
    integration = Integration(integration_path, config, _manifest=manifest)
    (integration_path / "__init__.py").write_text("", encoding="utf-8")
    if identity_provider_content is not None:
        (integration_path / "identity_provider.py").write_text(
            identity_provider_content, encoding="utf-8"
        )
    return integration


def _validate(integration: Integration, config: Config) -> str:
    """Validate one integration and return generated content."""
    return identity_provider.generate_and_validate(
        {integration.domain: integration}, config
    )


def test_valid_identity_provider(tmp_path: Path) -> None:
    """Test a valid identity provider integration."""
    config = _config(tmp_path)
    integration = _create_integration(tmp_path, "valid", config=config)

    _validate(integration, config)

    assert integration.errors == []


@pytest.mark.parametrize(
    ("manifest_extra", "expected_error"),
    [
        pytest.param(
            {"dependencies": []},
            "must depend on `auth`",
            id="missing-auth-dependency",
        ),
        pytest.param(
            {"config_flow": False},
            "must set `config_flow: true`",
            id="missing-config-flow",
        ),
        pytest.param(
            {"requirements": ["example==1.0.0"]},
            "must not define requirements",
            id="requirements",
        ),
        pytest.param(
            {"integration_type": "hub"},
            "must set `integration_type: service`",
            id="wrong-integration-type",
        ),
    ],
)
def test_manifest_violations(
    tmp_path: Path, manifest_extra: dict, expected_error: str
) -> None:
    """Test manifest validation errors."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path, "manifest_violation", manifest_extra=manifest_extra, config=config
    )

    _validate(integration, config)

    assert len(integration.errors) == 1
    assert expected_error in integration.errors[0].error


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import aiohttp", id="import"),
        pytest.param("from aiohttp import ClientSession", id="from-import"),
        pytest.param(
            "from homeassistant.helpers import aiohttp_client", id="child-import"
        ),
        pytest.param("from homeassistant import auth", id="homeassistant-auth"),
        pytest.param(
            "import homeassistant.components.auth.models", id="auth-submodule"
        ),
        pytest.param("from homeassistant.helpers import *", id="wildcard-from-import"),
        pytest.param("import homeassistant.components.light", id="other-component"),
    ],
)
def test_import_violations(tmp_path: Path, source: str) -> None:
    """Test import allowlist violations."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path,
        "import_violation",
        identity_provider_content=f"""
{source}


def get_identity_provider(data, options):
    return None
""",
        config=config,
    )

    _validate(integration, config)

    assert len(integration.errors) == 1
    assert "import of" in integration.errors[0].error


def test_allowed_child_imports(tmp_path: Path) -> None:
    """Test allowed child imports from parent modules."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path,
        "allowed_child_imports",
        identity_provider_content="""
from homeassistant.components import auth
from homeassistant.helpers import selector
from urllib import parse


def get_identity_provider(data, options):
    return None
""",
        config=config,
    )

    _validate(integration, config)

    assert integration.errors == []


@pytest.mark.parametrize(
    ("path", "source", "errors"),
    [
        pytest.param(
            "identity_provider.py", "from .const import DOMAIN", 0, id="sibling"
        ),
        pytest.param("identity_provider.py", "from . import const", 0, id="package"),
        pytest.param(
            "sub/identity_helper.py", "from ..const import DOMAIN", 0, id="parent"
        ),
        pytest.param(
            "identity_provider.py",
            "from ..http import HomeAssistantView",
            1,
            id="other-component",
        ),
        pytest.param(
            "identity_provider.py",
            "from ...helpers import aiohttp_client",
            1,
            id="helpers",
        ),
        pytest.param(
            "sub/identity_helper.py", "from ... import http", 1, id="nested-escape"
        ),
    ],
)
def test_relative_imports(tmp_path: Path, path: str, source: str, errors: int) -> None:
    """Test relative imports have to stay inside the integration."""
    config = _config(tmp_path)
    integration = _create_integration(tmp_path, "relative_imports", config=config)
    file_path = integration.path / path
    file_path.parent.mkdir(exist_ok=True)
    file_path.write_text(
        f"{source}\n\n\ndef get_identity_provider(data, options):\n    return None\n",
        encoding="utf-8",
    )

    _validate(integration, config)

    assert len(integration.errors) == errors
    assert all(
        "outside the integration is not allowed" in error.error
        for error in integration.errors
    )


@pytest.mark.parametrize(
    "forbidden_call",
    [
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "eval",
        "exec",
        "globals",
        "locals",
        "open",
        "setattr",
        "vars",
    ],
)
def test_forbidden_call_violations(tmp_path: Path, forbidden_call: str) -> None:
    """Test forbidden function calls."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path,
        f"forbidden_{forbidden_call.strip('_')}",
        identity_provider_content=f"""
def get_identity_provider(data, options):
    {forbidden_call}()
    return None
""",
        config=config,
    )

    _validate(integration, config)

    assert len(integration.errors) == 1
    assert f"call to `{forbidden_call}` is not allowed" in integration.errors[0].error


@pytest.mark.parametrize(
    ("source", "expected_error"),
    [
        pytest.param(
            """
async def get_identity_provider(data, options):
    return None
""",
            "must not be async",
            id="async-get-identity-provider",
        ),
        pytest.param(
            """
def get_identity_provider(data, options, other):
    return None
""",
            "must have exactly two positional parameters",
            id="too-many-parameters",
        ),
        pytest.param(
            """
def get_identity_provider(entry):
    return None
""",
            "must have exactly two positional parameters",
            id="too-few-parameters",
        ),
        pytest.param(
            """
def get_identity_provider(data, options):
    return None

def public_helper():
    return None
""",
            "unexpected function `public_helper`",
            id="public-helper",
        ),
        pytest.param(
            """
async def _helper():
    return None

def get_identity_provider(data, options):
    return None
""",
            "unexpected function `_helper`",
            id="async-private-helper",
        ),
        pytest.param(
            """
class Helper:
    pass

def get_identity_provider(data, options):
    return None
""",
            "unexpected top-level ClassDef",
            id="class",
        ),
        pytest.param(
            """
print("bad")

def get_identity_provider(data, options):
    return None
""",
            "unexpected top-level Expr",
            id="top-level-statement",
        ),
        pytest.param(
            """
def _helper():
    return None
""",
            "must define exactly one `get_identity_provider` function",
            id="missing-get-identity-provider",
        ),
    ],
)
def test_identity_provider_shape_violations(
    tmp_path: Path, source: str, expected_error: str
) -> None:
    """Test identity_provider.py shape violations."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path, "shape_violation", identity_provider_content=source, config=config
    )

    _validate(integration, config)

    assert len(integration.errors) == 1
    assert expected_error in integration.errors[0].error


def test_without_identity_provider_ignored(tmp_path: Path) -> None:
    """Test integrations without identity_provider.py are ignored."""
    config = _config(tmp_path)
    integration = _create_integration(
        tmp_path,
        "ignored",
        manifest_extra={"dependencies": [], "config_flow": False},
        identity_provider_content=None,
        config=config,
    )

    content = _validate(integration, config)

    assert integration.errors == []
    assert "IDENTITY_PROVIDERS: Final[list[str]] = []" in content


def test_non_core_identity_provider_ignored(tmp_path: Path) -> None:
    """Test custom identity provider integrations are ignored."""
    config = _config(tmp_path)
    integration_path = tmp_path / "custom_components/custom_idp"
    integration_path.mkdir(parents=True)
    (integration_path / "identity_provider.py").write_text(
        "import aiohttp\n", encoding="utf-8"
    )
    integration = Integration(
        integration_path,
        config,
        _manifest={
            "domain": "custom_idp",
            "name": "custom_idp",
            "documentation": "https://example.com",
            "codeowners": ["@awesome"],
        },
    )

    content = _validate(integration, config)

    assert integration.errors == []
    assert "IDENTITY_PROVIDERS: Final[list[str]] = []" in content


def test_generated_content(tmp_path: Path) -> None:
    """Test generated identity provider content."""
    config = _config(tmp_path)
    zeta = _create_integration(tmp_path, "zeta", config=config)
    alpha = _create_integration(tmp_path, "alpha", config=config)

    content = identity_provider.generate_and_validate(
        {"zeta": zeta, "alpha": alpha}, config
    )

    assert (
        content
        == '''"""Automatically generated file.

To update, run python3 -m script.hassfest
"""

from typing import Final

IDENTITY_PROVIDERS: Final[list[str]] = [
    "alpha",
    "zeta",
]
'''
    )


@pytest.mark.parametrize(
    ("source", "errors"),
    [
        pytest.param(
            """
from homeassistant.components.auth import IdentityProviderConfigFlow


class ValidFlow(IdentityProviderConfigFlow, domain="valid"):
    pass
""",
            [],
            id="base-class",
        ),
        pytest.param(
            """
from homeassistant.components import auth


class ValidFlow(auth.IdentityProviderConfigFlow, domain="valid"):
    pass
""",
            [],
            id="attribute-base-class",
        ),
        pytest.param(
            """
from homeassistant.config_entries import ConfigFlow


class CustomFlow(ConfigFlow, domain="valid"):
    pass
""",
            [
                "`CustomFlow` must subclass `IdentityProviderConfigFlow` instead of a "
                "generic flow"
            ],
            id="config-flow",
        ),
        pytest.param(
            """
from homeassistant.config_entries import OptionsFlow


class CustomOptionsFlow(OptionsFlow):
    pass
""",
            [
                "`CustomOptionsFlow` must subclass `IdentityProviderConfigFlow` "
                "instead of a generic flow"
            ],
            id="options-flow",
        ),
        pytest.param(
            """
from .other import SomeFlow


class CustomFlow(SomeFlow, domain="valid"):
    pass
""",
            ["`CustomFlow` must subclass `IdentityProviderConfigFlow`"],
            id="other-base",
        ),
    ],
)
def test_config_flow_shape(tmp_path: Path, source: str, errors: list[str]) -> None:
    """Test config flows have to build on the identity provider flow base."""
    config = _config(tmp_path)
    integration = _create_integration(tmp_path, "valid", config=config)
    (integration.path / "config_flow.py").write_text(source, encoding="utf-8")

    _validate(integration, config)

    assert [error.error for error in integration.errors] == [
        f"config_flow.py: {error}" for error in errors
    ]
