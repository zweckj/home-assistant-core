"""Fixtures for the Google Sign-In tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.core import HomeAssistant


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
    """Mock setting up a Google Sign-In config entry."""
    with patch(
        "homeassistant.components.google_sign_in.async_setup_entry", return_value=True
    ) as mock:
        yield mock


@pytest.fixture
def redirect_url(hass: HomeAssistant) -> None:
    """Set a Home Assistant URL for redirect URI generation."""
    hass.config.external_url = "https://example.com"
