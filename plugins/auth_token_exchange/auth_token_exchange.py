# type: ignore
"""Plugin to exchange token.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Abhishek Singh

This module loads configurations for plugins.
"""

import logging
import os
import sys
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
# Avoid duplicate handlers when workers reload or module is imported multiple times
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)  # or INFO
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
logger.setLevel(logging.DEBUG)  # raise level for this module
logger.propagate = False  # prevent double-printing via root/uvicorn handlers


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

        #
        #
        # Extract Bearer token from headers
        headers = payload.headers.root if payload.headers is not None else {}
        auth_header = None
        # Normalize header lookup
        logger.info(f"[TokenExchange] (tool_pre_invoke) Found Bearer token in header '{headers.keys()}' : {headers}")
        for key in ["tc-token"]:
            if key in headers:
                auth_header = headers[key]
                logger.info(f"[TokenExchange] (tool_pre_invoke) Found Bearer token in header '{key}': {auth_header}")
                break
        # if not auth_header:
        #     for key in ["authorization", "Authorization"]:
        #         if key in headers:
        #             auth_header = headers[key]
        #             logger.info(f"[TokenExchange] (tool_pre_invoke) Found Bearer token in header '{key}': {auth_header}")
        #             break

        incoming_token = None
        if isinstance(auth_header, str) and auth_header.lower().startswith("bearer "):
            incoming_token = auth_header[7:].strip()
        #
        #

        # # Check that 'tc_token' is present in context.state
        # logger.info(f"Checking for tc_token in context.state: {context.global_context.state.keys()}")
        # if "tc_token" not in context.global_context.state:
        #     logger.error("No tc_token in context.state.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="missing token context",
        #             description="Missing 'tc_token' in context.state.",
        #             code="MISSING_TC_TOKEN",
        #         ),
        #     )
        # logger.info("Got tc_token from context.state.")
        #
        # # Validate structure of 'tc_token'
        # token_entries = context.global_context.state["tc_token"]
        # if not isinstance(token_entries, list):
        #     logger.error("tc_token is not a list.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="token context is not a list",
        #             description="Expected 'tc_token' to be a list of entries.",
        #             code="TC_TOKEN_NOT_LIST",
        #         ),
        #     )
        # logger.info("Got a valid tc_token list.")
        #
        # if not token_entries:
        #     logger.error("tc_token is empty.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="token context empty",
        #             description="'tc_token' is an empty list.",
        #             code="TC_TOKEN_EMPTY",
        #         ),
        #     )
        # logger.info("Got a non-empty tc_token list.")
        #
        # if not isinstance(token_entries[-1], dict):
        #     logger.error("Last entry in tc_token is not a dict.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="last tc token entry not a dict",
        #             description="Latest entry in 'tc_token' must be a dict containing 'token'.",
        #             code="LAST_ENTRY_NOT_DICT",
        #         ),
        #     )
        # logger.info("Got a valid last entry in tc_token.")
        #
        # last_entry = token_entries[-1]
        # if "token" not in last_entry:
        #     logger.error("Last entry in tc_token does not include a token.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="token field missing in last entry",
        #             description="Latest entry in 'tc_token' does not include a 'token' field.",
        #             code="TOKEN_FIELD_MISSING",
        #         ),
        #     )
        # logger.info("Last entry in tc_token includes a token.")
        #
        # incoming_token = last_entry.get("token")
        # if not isinstance(incoming_token, str):
        #     logger.error("Last entry in tc_token does not include a string token.")
        #     return ToolPreInvokeResult(
        #         continue_processing=False,
        #         violation=PluginViolation(
        #             reason="token not a string",
        #             description="Latest 'tc_token' entry 'token' must be a string.",
        #             code="TOKEN_NOT_STRING",
        #         ),
        #     )

        if not incoming_token:
            logger.error("No Bearer token found in headers.")
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="no Bearer token found in headers",
                    description="No Bearer token found in headers.",
                    code="NO_BEARER_TOKEN",
                ),
            )

        if incoming_token == "":
            logger.error("Last entry in tc_token includes an empty string token.")
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="token is empty",
                    description="Latest 'tc_token' entry 'token' is an empty string.",
                    code="TOKEN_EMPTY",
                ),
            )
        # norm_token = incoming_token.strip().lower()
        # if "redacted" in norm_token:
        #     letters_only = "".join(ch for ch in norm_token if ch.isalpha())
        #     if letters_only == "redacted":
        #         logger.info("Last entry in tc_token includes a redacted token.")
        #         return ToolPreInvokeResult(
        #             continue_processing=False,
        #             violation=PluginViolation(
        #                 reason="redacted token",
        #                 description="The token is redacted.",
        #                 code="TOKEN_REDACTED",
        #             ),
        #         )

        logger.info(f"Got an Incoming Token. {incoming_token}")

        try:
            exchanged_token = self.oauth_client.token_exchange(subject_token=incoming_token, new_scopes=self.cfg["scopes"].split(" "))
        except Exception as exc:  # Broad by design to surface as violation without crashing
            logger.error(f"Token exchange failed: {type(exc).__name__}: {str(exc)}")
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
            logger.error("Token exchange response did not include a usable 'access_token'.")
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
        existing = context.global_context.state.get("tc_token")
        if isinstance(existing, list):
            existing.append(token_entry)
        else:
            context.global_context.state["tc_token"] = [token_entry]

        return ToolPreInvokeResult(continue_processing=True)
