# type: ignore
"""Plugin to exchange token.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Abhishek Singh

This module loads configurations for plugins.
"""

import logging
import os
from typing import Dict

from dotenv import load_dotenv

from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from mcpgateway.plugins.framework.models import PluginViolation
from plugins.auth_token_exchange.oauth_lib import OAuthClient, OAuthClientConfig

logger = logging.getLogger(__name__)


def _load_oauth_config() -> Dict[str, str]:
    load_dotenv()
    token_endpoint = os.getenv("OAUTH_TOKEN_ENDPOINT", "")
    client_id = os.getenv("OAUTH_CLIENT_ID", "")
    client_secret = os.getenv("OAUTH_CLIENT_SECRET", "")
    scopes = os.getenv("OAUTH_SCOPES", "")

    if not token_endpoint or not client_id or not client_secret or not scopes:
        raise ValueError("Missing required OAuth env variables")

    return {
        "token_endpoint": token_endpoint,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": scopes,
    }


class TokenExchange(Plugin):
    """Plugin to exchange token."""

    def __init__(self, config: PluginConfig):
        """Entry init block for plugin.

        Args:
          logger: logger that the skill can make use of
          config: the skill configuration
        """
        super().__init__(config)

        self.cfg = _load_oauth_config()

        self.oauth_config = OAuthClientConfig(
            token_endpoint=self.cfg["token_endpoint"],
            client_id=self.cfg["client_id"],
            client_secret=self.cfg["client_secret"],
            default_scopes=self.cfg["scopes"],
        )
        self.oauth_client = OAuthClient(self.oauth_config)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Plugin hook run before a tool is invoked.

        Args:
            payload: The tool payload to be analyzed.
            context: Contextual information about the hook call.

        Returns:
            The result of the plugin's analysis, including whether the tool can proceed.
        """

        # Check that 'tc_token' is present in context.state
        if "tc_token" not in context.state:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="missing token context",
                    description="Missing 'tc_token' in context.state.",
                    code="MISSING_TC_TOKEN",
                ),
            )

        # Validate structure of 'tc_token'
        token_entries = context.state["tc_token"]
        if not isinstance(token_entries, list):
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token context is not a list",
                    description="Expected 'tc_token' to be a list of entries.",
                    code="TC_TOKEN_NOT_LIST",
                ),
            )

        if not token_entries:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token context empty",
                    description="'tc_token' is an empty list.",
                    code="TC_TOKEN_EMPTY",
                ),
            )

        if not isinstance(token_entries[-1], dict):
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="last tc token entry not a dict",
                    description="Latest entry in 'tc_token' must be a dict containing 'token'.",
                    code="LAST_ENTRY_NOT_DICT",
                ),
            )

        last_entry = token_entries[-1]
        if "token" not in last_entry:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token field missing in last entry",
                    description="Latest entry in 'tc_token' does not include a 'token' field.",
                    code="TOKEN_FIELD_MISSING",
                ),
            )

        incoming_token = last_entry.get("token")
        if not isinstance(incoming_token, str):
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token not a string",
                    description="Latest 'tc_token' entry 'token' must be a string.",
                    code="TOKEN_NOT_STRING",
                ),
            )
        if incoming_token == "":
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token is empty",
                    description="Latest 'tc_token' entry 'token' is an empty string.",
                    code="TOKEN_EMPTY",
                ),
            )
        norm_token = incoming_token.strip().lower()
        if "redacted" in norm_token:
            letters_only = "".join(ch for ch in norm_token if ch.isalpha())
            if letters_only == "redacted":
                return ToolPreInvokeResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="redacted token",
                        description="The token is redacted.",
                        code="TOKEN_REDACTED",
                    ),
                )

        logger.info("Got an Incoming Token.")

        try:
            exchanged_token = self.oauth_client.token_exchange(subject_token=incoming_token, new_scopes=self.cfg["scopes"].split(" "))
        except Exception as exc:  # Broad by design to surface as violation without crashing
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="oauth token exchange failed",
                    description=f"Token exchange failed: {type(exc).__name__}: {str(exc)}",
                    code="OAUTH_EXCHANGE_FAILED",
                ),
            )

        exchanged_access_token = exchanged_token.get("access_token") if isinstance(exchanged_token, dict) else None
        if not isinstance(exchanged_access_token, str) or not exchanged_access_token:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Token Exchange Failed. Got empty token.",
                    description="Token exchange response did not include a usable 'access_token'.",
                    code="TOKEN_EXCHANGE_FAILED",
                ),
            )
        logger.info("Token Exchange successful.")

        # Append to the same list with explicit source
        token_entry = {"token": exchanged_access_token, "source": "exchange"}
        context.state["tc_token"].append(token_entry)

        return ToolPreInvokeResult(continue_processing=True)
