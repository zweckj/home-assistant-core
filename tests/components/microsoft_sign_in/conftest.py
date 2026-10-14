"""Fixtures for Microsoft Sign-In tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.core import HomeAssistant


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
    """Mock setting up a Microsoft Sign-In config entry."""
    with patch(
        "homeassistant.components.microsoft_sign_in.async_setup_entry",
        return_value=True,
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_unload_entry() -> Generator[AsyncMock]:
    """Mock unloading a Microsoft Sign-In config entry."""
    with patch(
        "homeassistant.components.microsoft_sign_in.async_unload_entry",
        return_value=True,
    ) as mock_unload:
        yield mock_unload


@pytest.fixture
def ha_url(hass: HomeAssistant) -> None:
    """Set a Home Assistant URL for redirect URI discovery."""
    hass.config.external_url = "https://example.com"
