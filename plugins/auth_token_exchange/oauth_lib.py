# type: ignore

from typing import Optional

from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import JsonWebKey, JsonWebToken
import requests


class OAuthClientConfig:
    def __init__(
        self,
        authorize_endpoint: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        introspection_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        default_scopes: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
    ):
        self.token_endpoint = token_endpoint
        self.introspection_endpoint = introspection_endpoint
        self.jwks_uri = jwks_uri
        self.authorize_endpoint = authorize_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.default_scopes = default_scopes
        self.redirect_uri = redirect_uri
        self.oidc_issuer = oidc_issuer


class OAuthClient:
    def __init__(self, config: OAuthClientConfig):
        self.config = config
        self.client = OAuth2Session(
            client_id=config.client_id,
            client_secret=config.client_secret,
        )
        self.state: Optional[str] = None

    def create_login_url(self, scopes: Optional[list[str]] = None):
        if not self.config.authorize_endpoint:
            raise ValueError("authorize_endpoint is required")

        if not self.config.redirect_uri:
            raise ValueError("redirect_uri is required")

        default_scopes = self.config.default_scopes or ""
        scopes = scopes or default_scopes.split(" ")

        uri, state = self.client.create_authorization_url(
            self.config.authorize_endpoint,
            redirect_uri=self.config.redirect_uri,
            scope=" ".join(scopes),
        )

        self.state = state
        return uri

    def exchange_code_for_token(self, code: str):
        if not self.config.token_endpoint:
            raise ValueError("token_endpoint is required")
        return self.client.fetch_token(
            url=self.config.token_endpoint,
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.config.redirect_uri,
            auth=(self.config.client_id, self.config.client_secret),
        )

    def validate_jwt(self, token: str):
        if not self.config.jwks_uri:
            raise ValueError("jwks_uri is required")
        jwks = requests.get(self.config.jwks_uri).json()
        jwk_set = JsonWebKey.import_key_set(jwks)
        jwt = JsonWebToken(["RS256", "ES256"])
        claims = jwt.decode(token, jwk_set)
        claims.validate()
        return claims

    def extract_claims(self, token: str):
        return self.validate_jwt(token)

    def refresh_token(self, refresh_token: str, scopes: Optional[list[str]] = None):
        scope_str = " ".join(scopes) if scopes else None

        return self.client.refresh_token(
            url=self.config.token_endpoint,
            refresh_token=refresh_token,
            scope=scope_str,
        )

    def token_exchange(self, subject_token: str, new_scopes: Optional[list[str]] = None):
        if not self.config.token_endpoint:
            raise ValueError("token_endpoint is required")
        if not self.config.client_id:
            raise ValueError("client_id is required")
        if not self.config.client_secret:
            raise ValueError("client_secret is required")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if new_scopes:
            data["scope"] = " ".join(new_scopes)

        return self.client.post(
            self.config.token_endpoint,
            data=data,
            auth=(self.config.client_id, self.config.client_secret),
        ).json()

    def validate_id_token(self, id_token: str):
        return self.validate_jwt(id_token)
