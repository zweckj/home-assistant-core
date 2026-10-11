"""Validate identity provider integrations."""

import ast
from pathlib import Path

from . import ast_parse_module
from .model import Config, Integration
from .serializer import format_python_namespace

PLUGIN = "identity_provider"

_ALLOWED_EXACT_IMPORTS = {
    "__future__",
    "collections.abc",
    "dataclasses",
    "datetime",
    "enum",
    "functools",
    "logging",
    "re",
    "types",
    "typing",
    "urllib.parse",
    "uuid",
    "probatio",
    "homeassistant.config_entries",
    "homeassistant.const",
    "homeassistant.core",
    "homeassistant.data_entry_flow",
    "homeassistant.exceptions",
    "homeassistant.helpers.config_validation",
    "homeassistant.helpers.selector",
    "homeassistant.helpers.typing",
    "homeassistant.components.auth",
}
_FORBIDDEN_CALLS = {
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
}


def _is_allowed_import(module: str) -> bool:
    """Return if the module is allowed."""
    return module in _ALLOWED_EXACT_IMPORTS


def _validate_import(module: str, integration: Integration, file_path: Path) -> None:
    """Validate an imported module."""
    if _is_allowed_import(module):
        return

    integration.add_error(
        PLUGIN,
        f"{file_path}: import of `{module}` is not allowed for identity providers",
    )


def _validate_import_from(
    node: ast.ImportFrom, integration: Integration, file_path: Path
) -> None:
    """Validate a from-import."""
    if node.level:
        # Each level past the first climbs one package up from the file.
        if node.level - 1 > len(file_path.parent.parts):
            integration.add_error(
                PLUGIN,
                f"{file_path}: import of `{'.' * node.level}{node.module or ''}` "
                "outside the integration is not allowed for identity providers",
            )
        return
    if node.module is None or _is_allowed_import(node.module):
        return

    for alias in node.names:
        _validate_import(f"{node.module}.{alias.name}", integration, file_path)


class _IdentityProviderVisitor(ast.NodeVisitor):
    """Validate identity provider Python modules."""

    def __init__(self, integration: Integration, file_path: Path) -> None:
        """Initialize the visitor."""
        self.integration = integration
        self.file_path = file_path

    def visit_Import(self, node: ast.Import) -> None:
        """Validate imports."""
        for alias in node.names:
            _validate_import(alias.name, self.integration, self.file_path)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Validate from-imports."""
        _validate_import_from(node, self.integration, self.file_path)

    def visit_Call(self, node: ast.Call) -> None:
        """Validate function calls."""
        if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
            self.integration.add_error(
                PLUGIN,
                f"{self.file_path}: call to `{node.func.id}` is not allowed "
                "for identity providers",
            )
        self.generic_visit(node)


def _validate_python_files(integration: Integration) -> None:
    """Validate Python files for import and call restrictions."""
    for file_path in sorted(integration.path.glob("**/*.py")):
        if not file_path.is_file():
            continue
        module = ast_parse_module(file_path)
        _IdentityProviderVisitor(
            integration, file_path.relative_to(integration.path)
        ).visit(module)


def _validate_manifest(integration: Integration) -> None:
    """Validate manifest restrictions."""
    if "auth" not in integration.dependencies:
        integration.add_error(
            PLUGIN,
            "Identity provider integrations must depend on `auth`",
        )
    if not integration.config_flow:
        integration.add_error(
            PLUGIN,
            "Identity provider integrations must set `config_flow: true`",
        )
    if integration.requirements:
        integration.add_error(
            PLUGIN,
            "Identity provider integrations must not define requirements",
        )
    if integration.manifest.get("integration_type") != "service":
        integration.add_error(
            PLUGIN,
            "Identity provider integrations must set `integration_type: service`",
        )


def _validate_get_identity_provider(
    node: ast.FunctionDef | ast.AsyncFunctionDef, integration: Integration
) -> None:
    """Validate get_identity_provider."""
    if isinstance(node, ast.AsyncFunctionDef):
        integration.add_error(
            PLUGIN,
            "identity_provider.py: `get_identity_provider` must not be async",
        )
        return

    args = node.args
    positional_args = [*args.posonlyargs, *args.args]
    if (
        len(positional_args) != 1
        or args.vararg
        or args.kwonlyargs
        or args.kwarg
        or args.defaults
    ):
        integration.add_error(
            PLUGIN,
            "identity_provider.py: `get_identity_provider` must have exactly one "
            "positional parameter",
        )


def _validate_identity_provider_shape(integration: Integration) -> None:
    """Validate identity_provider.py structure."""
    module = ast_parse_module(integration.path / "identity_provider.py")
    get_identity_provider_count = 0

    for index, node in enumerate(module.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if isinstance(node, ast.Import | ast.ImportFrom | ast.Assign | ast.AnnAssign):
            continue
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.name == "get_identity_provider":
                get_identity_provider_count += 1
                _validate_get_identity_provider(node, integration)
                continue
            if node.name.startswith("_") and isinstance(node, ast.FunctionDef):
                continue
            integration.add_error(
                PLUGIN,
                f"identity_provider.py: unexpected function `{node.name}`",
            )
            continue

        integration.add_error(
            PLUGIN,
            f"identity_provider.py: unexpected top-level {type(node).__name__}",
        )

    if get_identity_provider_count != 1:
        integration.add_error(
            PLUGIN,
            "identity_provider.py: must define exactly one `get_identity_provider` function",
        )


def _base_names(node: ast.ClassDef) -> set[str]:
    """Return the names of the direct bases of a class."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def has_identity_provider_flow(module: ast.Module) -> bool:
    """Return whether the module defines a flow on the identity provider base.

    The base implements the reconfigure step and the unique ID handling, so
    the quality scale validators accept it in place of those methods.
    """
    return any(
        isinstance(node, ast.ClassDef)
        and "IdentityProviderConfigFlow" in _base_names(node)
        for node in module.body
    )


def _validate_config_flow_shape(integration: Integration) -> None:
    """Validate config flows build on the identity provider flow base."""
    config_flow_path = integration.path / "config_flow.py"
    if not config_flow_path.is_file():
        return
    module = ast_parse_module(config_flow_path)
    for node in module.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = _base_names(node)
        if bases & {"ConfigFlow", "OptionsFlow"}:
            integration.add_error(
                PLUGIN,
                f"config_flow.py: `{node.name}` must subclass "
                "`IdentityProviderConfigFlow` instead of a generic flow",
            )
        elif any(keyword.arg == "domain" for keyword in node.keywords) and not bases & {
            "IdentityProviderConfigFlow"
        }:
            integration.add_error(
                PLUGIN,
                f"config_flow.py: `{node.name}` must subclass "
                "`IdentityProviderConfigFlow`",
            )


def generate_and_validate(integrations: dict[str, Integration], config: Config) -> str:
    """Validate and generate identity provider data."""
    domains = []
    for domain in sorted(integrations):
        integration = integrations[domain]
        if (
            not integration.core
            or not (integration.path / "identity_provider.py").is_file()
        ):
            continue

        domains.append(domain)
        _validate_manifest(integration)
        _validate_python_files(integration)
        _validate_identity_provider_shape(integration)
        _validate_config_flow_shape(integration)

    return format_python_namespace(
        {"IDENTITY_PROVIDERS": domains},
        annotations={"IDENTITY_PROVIDERS": "Final[list[str]]"},
    )


def validate(integrations: dict[str, Integration], config: Config) -> None:
    """Validate identity provider integrations."""
    identity_provider_path = (
        config.root / "homeassistant/generated/identity_providers.py"
    )
    config.cache["identity_providers"] = content = generate_and_validate(
        integrations, config
    )

    if config.specific_integrations:
        return

    if identity_provider_path.read_text(encoding="utf-8") != content:
        config.add_error(
            PLUGIN,
            "File identity_providers.py is not up to date. "
            "Run python3 -m script.hassfest",
            fixable=True,
        )


def generate(integrations: dict[str, Integration], config: Config) -> None:
    """Generate identity provider data."""
    identity_provider_path = (
        config.root / "homeassistant/generated/identity_providers.py"
    )
    identity_provider_path.write_text(
        f"{config.cache['identity_providers']}", encoding="utf-8"
    )
