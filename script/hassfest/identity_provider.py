"""Helpers for integrations that let users sign in with an identity provider."""

import ast


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
