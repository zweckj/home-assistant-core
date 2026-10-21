"""Fixtures for GitHub Sign-In tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.github_sign_in.const import DOMAIN
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

CLIENT_ID = "github-client-id"
CLIENT_SECRET = "github-client-secret"
NEW_CLIENT_ID = "new-github-client-id"
NEW_CLIENT_SECRET = "new-github-client-secret"
TITLE = "GitHub"
USER_INPUT = {CONF_CLIENT_ID: CLIENT_ID, CONF_CLIENT_SECRET: CLIENT_SECRET}
NEW_USER_INPUT = {CONF_CLIENT_ID: NEW_CLIENT_ID, CONF_CLIENT_SECRET: NEW_CLIENT_SECRET}


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
    """Mock setting up a config entry."""
    with patch(
        "homeassistant.components.github_sign_in.async_setup_entry", return_value=True
    ) as mock_setup_entry:
        yield mock_setup_entry


@pytest.fixture
def github_sign_in_entry() -> MockConfigEntry:
    """Return a GitHub Sign-In config entry."""
    return MockConfigEntry(domain=DOMAIN, title=TITLE, data=USER_INPUT)


@pytest.fixture
def external_url(hass: HomeAssistant) -> None:
    """Set an external URL on Home Assistant."""
    hass.config.external_url = "https://example.com"
