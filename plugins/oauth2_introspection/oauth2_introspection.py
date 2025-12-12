# type: ignore
"""OAuth2 Introspection Authentication Plugin

This plugin validates Bearer tokens via an RFC 7662 introspection endpoint exposed by Identity Provider (IDP)
and returns a resolved user to the gateway using the HTTP_AUTH_RESOLVE_USER hook.

Downstream propagation:
- Stores {"token", "introspection"} in plugin context state under key "tc_token". It is stored as an element in list.
"""

from __future__ import annotations

import base64
import json
import logging
import sys
from typing import Any, Optional

import aiohttp
from pydantic import BaseModel, Field

from mcpgateway.plugins.framework import (
    HttpAuthResolveUserPayload,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PluginViolationError,
)
from mcpgateway.plugins.framework.hooks.http import HttpAuthResolveUserResult
from mcpgateway.plugins.framework.models import PluginResult

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


class OAuth2IntrospectionConfig(BaseModel):
    """
    Configuration class for OAuth2 token introspection.
    This class serves as a configuration model for setting up OAuth2 token introspection parameters.

    Attributes:
        introspection_url: The URL of the OAuth2 introspection endpoint used to validate tokens.
        client_id: The client identifier required to authenticate with the introspection endpoint.
        client_secret: The client secret associated with the client identifier.
        auth_method: The authentication method to be used for the introspection request.
            Default is "basic". Options are "basic" or "post".
        audience: Optional field specifying the intended audience of the tokens being introspected.
        required_scopes: Optional list of required scopes to validate against the token claims.
        expose_raw_token_in_context: A boolean flag indicating whether the raw token should be exposed
            in the introspection context. Default is False.
        request_timeout_seconds: The maximum duration in seconds to wait for a response from the
            introspection endpoint. Default is 30 seconds.
    """

    introspection_url: str
    client_id: str
    client_secret: str
    auth_method: str = Field(default="basic", description="basic | post")
    audience: Optional[str] = None
    required_scopes: list[str] | None = None
    expose_raw_token_in_context: bool = False
    request_timeout_seconds: int = 30


class OAuth2IntrospectionPlugin(Plugin):
    """
    Represents a plugin for handling OAuth2 token introspection.

    This plugin is intended for use in environments where access tokens issued by an identity provider (IDP) need to
    be introspected to validate their authenticity, audience, and associated scopes.
    It supports integration with IDP services and provides user resolution capabilities.

    Attributes:
        _cfg: Instance of PluginConfig that holds the configuration settings for this plugin.
    """

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        self._cfg = OAuth2IntrospectionConfig(**(config.config or {}))
        logger.info("[OAuth2Introspection] Initialized")

    @staticmethod
    def _get_jwt_issuer(token: str) -> Optional[str]:
        """Attempt to parse a JWT and return its 'iss' claim if present.

        This performs a structural decode only (no signature verification).
        Returns None if the token is not a parseable JWT.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            # pad base64url if needed
            padding = "=" * (-len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
            payload = json.loads(payload_bytes.decode("utf-8"))
            iss = payload.get("iss")
            if isinstance(iss, str):
                return iss
            return None
        except Exception:
            return None

    async def http_auth_resolve_user(self, payload: HttpAuthResolveUserPayload, context: PluginContext) -> HttpAuthResolveUserResult:
        # Extract token from credentials or headers
        token: Optional[str] = None
        if payload.credentials is not None:
            scheme = str(payload.credentials.get("scheme") or "").lower()
            if scheme == "bearer":
                cred_val = payload.credentials.get("credentials")
                token = str(cred_val) if cred_val is not None else None

        if not token:
            # fall back to standard JWT/API token validation
            logger.info("[OAuth2Introspection] No token found in credentials, continuing to standard auth")
            return PluginResult(
                continue_processing=True,
                metadata={"custom_auth": "not_applicable"},
            )

        # If the token is a valid JWT and issuer is our gateway, fall back (do not introspect)
        issuer = self._get_jwt_issuer(token)
        if issuer == "mcpgateway":
            logger.info("[OAuth2Introspection] Skipping introspection for JWT issued by gateway.")
            return PluginResult(
                continue_processing=True,
                metadata={"custom_auth": "not_applicable"},
            )

        # Call IDP introspection API
        logger.info("[OAuth2Introspection] Introspecting token with IDP.")
        introspection: dict[str, Any]
        try:
            data: dict[str, str] = {"token": token}
            post_headers: dict[str, str] = {}
            auth: aiohttp.BasicAuth | None = None
            if self._cfg.auth_method == "basic":
                auth = aiohttp.BasicAuth(self._cfg.client_id, self._cfg.client_secret)
            else:
                data["client_id"] = self._cfg.client_id
                data["client_secret"] = self._cfg.client_secret

            timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_seconds)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self._cfg.introspection_url, data=data, headers=post_headers, auth=auth) as resp:
                    resp.raise_for_status()
                    introspection = await resp.json()
        except Exception as e:
            logger.error("[OAuth2Introspection] Introspection call failed: %s", e)
            raise PluginViolationError(
                message="Token introspection failed.",
                violation=PluginViolation(reason="Token introspection failed.", description=f"Token introspection failed: {e}", code="AUTH_ERROR"),
            )
        logger.info("[OAuth2Introspection] Introspection with IDP successful.")

        # Validate that the token is active
        if not introspection.get("active"):
            raise PluginViolationError(
                message="Inactive or invalid token",
                violation=PluginViolation(
                    reason="Inactive or invalid token",
                    description="The provided access token is inactive or invalid per introspection.",
                    code="INACTIVE_TOKEN",
                ),
            )

        # Validate the audience claim
        if self._cfg.audience:
            aud = introspection.get("aud") or introspection.get("client_id")
            if isinstance(aud, list):
                valid_audience = self._cfg.audience in aud
            else:
                valid_audience = aud == self._cfg.audience
            if not valid_audience:
                raise PluginViolationError(
                    message="Inactive or invalid token",
                    violation=PluginViolation(
                        reason="Audience mismatch",
                        description="Token audience does not match required audience.",
                        code="INVALID_AUDIENCE",
                    ),
                )

        # Validate the scopes
        valid_scopes = True
        missing_scopes: list[str] = []
        if self._cfg.required_scopes:
            token_scopes = introspection.get("scope") or introspection.get("scopes")
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
            token_scopes_set = set(token_scopes or [])
            required_set = set(self._cfg.required_scopes)
            missing_scopes = sorted(list(required_set - token_scopes_set))
            valid_scopes = len(missing_scopes) == 0
        if not valid_scopes:
            missing_scopes_str = ", ".join(missing_scopes)
            raise PluginViolationError(
                message="Required scopes not present",
                violation=PluginViolation(reason="Missing required scopes", description=f"The token is missing required scopes: {missing_scopes_str}", code="MISSING_REQUIRED_SCOPES"),
            )

        # Get the email associated with the token
        # Our IDP puts the email in the 'preferred_username' field
        # TODO: The field in the token to be used as email should be configurable
        email = introspection.get("email") or introspection.get("preferred_username")
        if not email:
            raise PluginViolationError(
                message="Unable to resolve user identity from token",
                violation=PluginViolation(
                    reason="Unresolvable identity",
                    description="Could not determine user identity (email) from introspection payload.",
                    code="UNRESOLVED_IDENTITY",
                ),
            )

        # Store token and introspection in plugin context.state for downstream usage
        token_entry = {
            "token": token if self._cfg.expose_raw_token_in_context else "***redacted***",
            "introspection": introspection,
        }
        existing = context.state.get("tc_token")
        if isinstance(existing, list):
            existing.append(token_entry)
        else:
            context.state["tc_token"] = [token_entry]

        # Return from plugin with validated user
        user_dict = {"email": email, "sub": introspection.get("sub"), "is_active": True}
        return PluginResult(modified_payload=user_dict, continue_processing=True, metadata={"auth_method": "oauth2"})
