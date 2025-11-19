"""Config flow for the AWS S3 integration."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from aiobotocore.client import AioBaseClient as S3Client
from aiobotocore.session import AioSession
from botocore.exceptions import ClientError, ConnectionError, ParamValidationError
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    AWS_DOMAIN,
    CONF_ACCESS_KEY_ID,
    CONF_BUCKET,
    CONF_ENDPOINT_URL,
    CONF_SECRET_ACCESS_KEY,
    DEFAULT_ENDPOINT_URL,
    DESCRIPTION_AWS_S3_DOCS_URL,
    DESCRIPTION_BOTO3_DOCS_URL,
    DOMAIN,
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ACCESS_KEY_ID): cv.string,
        vol.Required(CONF_SECRET_ACCESS_KEY): TextSelector(
            config=TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
        vol.Required(CONF_BUCKET): cv.string,
        vol.Required(CONF_ENDPOINT_URL, default=DEFAULT_ENDPOINT_URL): TextSelector(
            config=TextSelectorConfig(type=TextSelectorType.URL)
        ),
    }
)


class S3ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow initiated by the user."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._async_abort_entries_match(
                {
                    CONF_BUCKET: user_input[CONF_BUCKET],
                    CONF_ENDPOINT_URL: user_input[CONF_ENDPOINT_URL],
                }
            )

            if not urlparse(user_input[CONF_ENDPOINT_URL]).hostname.endswith(
                AWS_DOMAIN
            ):
                errors[CONF_ENDPOINT_URL] = "invalid_endpoint_url"
            else:
                try:
                    # Wrap client creation in executor to handle blocking I/O during
                    # botocore service definition loading. We use the import executor
                    # since loading service definitions is similar to importing modules.
                    def _create_client_sync() -> S3Client:
                        """Synchronously create S3 client in thread."""
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            session = AioSession()
                            client_cm = session.create_client(
                                "s3",
                                endpoint_url=user_input.get(CONF_ENDPOINT_URL),
                                aws_secret_access_key=user_input[
                                    CONF_SECRET_ACCESS_KEY
                                ],
                                aws_access_key_id=user_input[CONF_ACCESS_KEY_ID],
                            )
                            # pylint: disable-next=unnecessary-dunder-call
                            return loop.run_until_complete(client_cm.__aenter__())
                        finally:
                            loop.close()

                    client = await self.hass.async_add_import_executor_job(
                        _create_client_sync
                    )
                    try:
                        await client.head_bucket(Bucket=user_input[CONF_BUCKET])
                    finally:
                        # pylint: disable-next=unnecessary-dunder-call
                        await client.__aexit__(None, None, None)
                except ClientError:
                    errors["base"] = "invalid_credentials"
                except ParamValidationError as err:
                    if "Invalid bucket name" in str(err):
                        errors[CONF_BUCKET] = "invalid_bucket_name"
                except ValueError:
                    errors[CONF_ENDPOINT_URL] = "invalid_endpoint_url"
                except ConnectionError:
                    errors[CONF_ENDPOINT_URL] = "cannot_connect"
                else:
                    return self.async_create_entry(
                        title=user_input[CONF_BUCKET], data=user_input
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_DATA_SCHEMA, user_input
            ),
            errors=errors,
            description_placeholders={
                "aws_s3_docs_url": DESCRIPTION_AWS_S3_DOCS_URL,
                "boto3_docs_url": DESCRIPTION_BOTO3_DOCS_URL,
            },
        )
