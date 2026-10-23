"""Fixtures for the OpenID Connect integration tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.openid_connect.const import CONF_ISSUER, DOMAIN
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

ISSUER = "https://idp.example.com"
CLIENT_ID = "client-id"
CLIENT_SECRET = "client-secret"


@pytest.fixture(autouse=True)
def set_url(hass: HomeAssistant) -> None:
    """Set a Home Assistant URL for redirect URI discovery."""
    hass.config.external_url = "https://example.com"


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
    """Mock setting up a config entry."""
    with patch(
        "homeassistant.components.openid_connect.async_setup_entry",
        return_value=None,
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_config_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Return a mock OpenID Connect config entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="idp.example.com",
        unique_id=ISSUER,
        data={
            CONF_ISSUER: ISSUER,
            CONF_CLIENT_ID: CLIENT_ID,
            CONF_CLIENT_SECRET: CLIENT_SECRET,
        },
    )
    entry.add_to_hass(hass)
    return entry
