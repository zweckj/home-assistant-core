"""Mock inputs for tests."""
from homeassistant.components.acaia.const import CONF_IS_NEW_STYLE_SCALE, DOMAIN
from homeassistant.const import CONF_MAC, CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.service_info.bluetooth import BluetoothServiceInfo

from tests.common import MockConfigEntry

USER_INPUT = {
    CONF_MAC: "aa:bb:cc:dd:ee:ff",
    CONF_NAME: "LUNAR_1234",
    CONF_IS_NEW_STYLE_SCALE: True,
}

SERVICE_INFO = BluetoothServiceInfo(
    name="LUNAR_1234",
    address="aa:bb:cc:dd:ee:ff",
    rssi=-63,
    manufacturer_data={},
    service_data={},
    service_uuids=[],
    source="local",
)


async def init_integration(hass: HomeAssistant) -> MockConfigEntry:
    """Set up the Acaia integration in Home Assistant."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Home",
        entry_id="3bd2acb0e4f0476d40865546d0d91921",
        unique_id="123-456",
        data=USER_INPUT,
    )

    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    coordinator = hass.data[DOMAIN][entry.entry_id]

    coordinator._on_data_received(
        "",
        bytearray(b"\xef\xdd\x08\tZ\x02\x03\x01\x00\x01\x01\x01\x0e^"),
    )  # send a message with battery level of 90

    coordinator._on_data_received(
        "",
        bytearray(b"\xef\xdd\x0c\x08\x05\xe0\x08\x00\x00\x01\x00\xe9\r"),
    )  # send a message with weight of 227.2

    return entry
