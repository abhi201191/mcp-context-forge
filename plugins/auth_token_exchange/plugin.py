"""Plugin to exchange token.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Abhishek Singh

This module loads configurations for plugins.
"""

# First-Party
import os
from typing import Dict
from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

from mcpgateway.plugins.framework.models import PluginViolation
from plugins.auth_token_exchange.oauth_lib import OAuthClientConfig, OAuthClient


def _load_oauth_config() -> Dict[str, str]:
    token_endpoint = os.getenv("OAUTH_TOKEN_ENDPOINT")
    client_id = os.getenv("OAUTH_CLIENT_ID")
    client_secret = os.getenv("OAUTH_CLIENT_SECRET")
    scopes = os.getenv("OAUTH_SCOPES")

    if not token_endpoint or not client_id or not client_secret or not scopes:
        raise ValueError("Missing required OAuth env variables")

    return {
        "token_endpoint": token_endpoint,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": scopes
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
            default_scopes=self.cfg["scopes"]
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
        
        incoming_token = context.state["tc_token"][-1] if context.state["tc_token"] else None
        if incoming_token is None:
            return ToolPreInvokeResult(
                continue_processing=False, 
                violation=PluginViolation(
                    reason="invalid token",
                    description="incoming token not present",
                    code="NOT FOUND"
                ),
            ) 
        exchanged_token = self.oauth_client.token_exchange(
            subject_token=incoming_token,
            new_scopes=self.cfg["scopes"].split(" ")
        )

        exchanged_access_token = exchanged_token.get("access_token")

        if exchanged_access_token is not None:
            context.state["tc_token"].append(exchanged_access_token)

        return ToolPreInvokeResult(continue_processing=True)
