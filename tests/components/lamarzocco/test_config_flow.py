"""Test the La Marzocco config flow."""

from unittest.mock import MagicMock, patch

from lmcloud.exceptions import AuthFail, RequestNotSuccessful
from lmcloud.models import LaMarzoccoDeviceInfo

from homeassistant import config_entries
from homeassistant.components.lamarzocco.config_flow import CONF_MACHINE
from homeassistant.components.lamarzocco.const import DOMAIN
from homeassistant.const import CONF_HOST, CONF_MODEL, CONF_NAME, CONF_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult, FlowResultType

from . import USER_INPUT

from tests.common import MockConfigEntry


async def __do_successful_user_step(
    hass: HomeAssistant, result: FlowResult, mock_cloud_client: MagicMock
) -> FlowResult:
    """Successfully configure the user step."""
    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )
    await hass.async_block_till_done()

    assert result2["type"] == FlowResultType.FORM
    assert result2["step_id"] == "machine_selection"
    return result2


async def __do_sucessful_machine_selection_step(
    hass: HomeAssistant, result2: FlowResult, mock_device_info: LaMarzoccoDeviceInfo
) -> None:
    """Successfully configure the machine selection step."""

    with patch(
        "homeassistant.components.lamarzocco.config_flow.LaMarzoccoLocalClient.validate_connection",
        return_value=True,
    ):
        result3 = await hass.config_entries.flow.async_configure(
            result2["flow_id"],
            {
                CONF_HOST: "192.168.1.1",
                CONF_MACHINE: mock_device_info.serial_number,
            },
        )
    await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.CREATE_ENTRY

    assert result3["title"] == mock_device_info.serial_number
    assert result3["data"] == {
        **USER_INPUT,
        CONF_HOST: "192.168.1.1",
        CONF_MODEL: mock_device_info.model,
        CONF_NAME: mock_device_info.name,
        CONF_TOKEN: mock_device_info.communication_key,
    }


async def test_form(
    hass: HomeAssistant,
    mock_cloud_client: MagicMock,
    mock_device_info: LaMarzoccoDeviceInfo,
) -> None:
    """Test we get the form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {}
    assert result["step_id"] == "user"

    result2 = await __do_successful_user_step(hass, result, mock_cloud_client)
    await __do_sucessful_machine_selection_step(hass, result2, mock_device_info)

    # assert len(mock_cloud_client.check_local_connection.mock_calls) == 1


async def test_form_abort_already_configured(
    hass: HomeAssistant,
    mock_cloud_client: MagicMock,
    mock_device_info: LaMarzoccoDeviceInfo,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test we abort if already configured."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {}

    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )
    await hass.async_block_till_done()

    assert result2["type"] == FlowResultType.FORM
    assert result2["step_id"] == "machine_selection"

    result3 = await hass.config_entries.flow.async_configure(
        result2["flow_id"],
        {
            CONF_HOST: "192.168.1.1",
            CONF_MACHINE: mock_device_info.serial_number,
        },
    )
    await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.ABORT
    assert result3["reason"] == "already_configured"


async def test_form_invalid_auth(
    hass: HomeAssistant,
    mock_device_info: LaMarzoccoDeviceInfo,
    mock_cloud_client: MagicMock,
) -> None:
    """Test invalid auth error."""

    mock_cloud_client.get_customer_fleet.side_effect = AuthFail("")
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )

    assert result2["type"] == FlowResultType.FORM
    assert result2["errors"] == {"base": "invalid_auth"}
    assert len(mock_cloud_client.get_customer_fleet.mock_calls) == 1

    # test recovery from failure
    mock_cloud_client.get_customer_fleet.side_effect = None
    result2 = await __do_successful_user_step(hass, result, mock_cloud_client)
    await __do_sucessful_machine_selection_step(hass, result2, mock_device_info)


async def test_form_invalid_host(
    hass: HomeAssistant,
    mock_cloud_client: MagicMock,
    mock_device_info: LaMarzoccoDeviceInfo,
) -> None:
    """Test invalid auth error."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {}

    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )
    await hass.async_block_till_done()

    assert result2["type"] == FlowResultType.FORM
    assert result2["step_id"] == "machine_selection"

    with patch(
        "homeassistant.components.lamarzocco.config_flow.LaMarzoccoLocalClient.validate_connection",
        return_value=False,
    ):
        result3 = await hass.config_entries.flow.async_configure(
            result2["flow_id"],
            {
                CONF_HOST: "192.168.1.1",
                CONF_MACHINE: mock_device_info.serial_number,
            },
        )
    await hass.async_block_till_done()

    assert result3["type"] == FlowResultType.FORM
    assert result3["errors"] == {"host": "cannot_connect"}
    assert len(mock_cloud_client.get_customer_fleet.mock_calls) == 1

    # test recovery from failure
    await __do_sucessful_machine_selection_step(hass, result2, mock_device_info)


async def test_form_cannot_connect(
    hass: HomeAssistant,
    mock_cloud_client: MagicMock,
    mock_device_info: LaMarzoccoDeviceInfo,
) -> None:
    """Test cannot connect error."""

    mock_cloud_client.get_customer_fleet.return_value = {}

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )

    assert result2["type"] == FlowResultType.FORM
    assert result2["errors"] == {"base": "no_machines"}
    assert len(mock_cloud_client.get_customer_fleet.mock_calls) == 1

    mock_cloud_client.get_customer_fleet.side_effect = RequestNotSuccessful("")
    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        USER_INPUT,
    )

    assert result2["type"] == FlowResultType.FORM
    assert result2["errors"] == {"base": "cannot_connect"}
    assert len(mock_cloud_client.get_customer_fleet.mock_calls) == 2

    # test recovery from failure
    mock_cloud_client.get_customer_fleet.side_effect = None
    mock_cloud_client.get_customer_fleet.return_value = {
        mock_device_info.serial_number: mock_device_info
    }
    result2 = await __do_successful_user_step(hass, result, mock_cloud_client)
    await __do_sucessful_machine_selection_step(hass, result2, mock_device_info)


# async def test_reauth_flow(
#     hass: HomeAssistant, mock_lamarzocco: MagicMock, mock_config_entry: MockConfigEntry
# ) -> None:
#     """Test that the reauth flow."""

#     mock_config_entry.add_to_hass(hass)

#     result = await hass.config_entries.flow.async_init(
#         DOMAIN,
#         context={
#             "source": SOURCE_REAUTH,
#             "unique_id": mock_config_entry.unique_id,
#             "entry_id": mock_config_entry.entry_id,
#         },
#         data=mock_config_entry.data,
#     )

#     assert result["type"] == FlowResultType.FORM
#     assert result["step_id"] == "reauth_confirm"

#     result2 = await hass.config_entries.flow.async_configure(
#         result["flow_id"],
#         {CONF_PASSWORD: "new_password"},
#     )

#     assert result2["type"] == FlowResultType.ABORT
#     await hass.async_block_till_done()
#     assert result2["reason"] == "reauth_successful"
#     assert len(mock_lamarzocco.get_all_machines.mock_calls) == 1
#     assert mock_config_entry.data[CONF_PASSWORD] == "new_password"
