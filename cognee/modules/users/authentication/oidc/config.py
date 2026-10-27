import os
from dataclasses import dataclass
from uuid import UUID

# Fixed namespace for ids derived from the IdP: users from (issuer, sub), tenants
# from group names. Changing it re-keys every OIDC user and tenant.
OIDC_NAMESPACE = UUID("6f1c8a52-3d4e-4b9a-9c1d-2e7f0a5b8c31")


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audiences: tuple[str, ...]
    allowed_tenant_groups: tuple[str, ...]
    superuser_group: str
    client_id: str
    client_secret: str
    redirect_uri: str
    allowed_return_to: tuple[str, ...]
    # "{tenant}" formats of the groups that make someone an editor or a reader of
    # a tenant. Both empty: the tenant's own group grants everything, as before.
    editor_group_format: str = ""
    reader_group_format: str = ""

    def __post_init__(self) -> None:
        formats = (self.editor_group_format, self.reader_group_format)
        if any(formats) and not all("{tenant}" in fmt for fmt in formats):
            raise ValueError(
                "OIDC_EDITOR_GROUP_FORMAT and OIDC_READER_GROUP_FORMAT are set together, "
                "each with a {tenant} placeholder"
            )
        if any(formats) and formats[0] == formats[1]:
            raise ValueError("the editor and reader group formats must differ")

    @property
    def uses_role_groups(self) -> bool:
        return bool(self.editor_group_format)

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}oidc/certs"

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.issuer}oidc/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}oidc/token"


def is_oidc_mode() -> bool:
    return os.getenv("AUTH_MODE", "").strip().lower() == "oidc"


def get_oidc_settings() -> OIDCSettings:
    return OIDCSettings(
        issuer=os.getenv("OIDC_ISSUER", ""),
        audiences=_csv("OIDC_AUDIENCES"),
        allowed_tenant_groups=_csv("OIDC_ALLOWED_TENANT_GROUPS"),
        superuser_group=os.getenv("OIDC_SUPERUSER_GROUP", "").strip(),
        client_id=os.getenv("OIDC_CLIENT_ID", ""),
        client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
        redirect_uri=os.getenv("OIDC_REDIRECT_URI", ""),
        allowed_return_to=_csv("OIDC_ALLOWED_RETURN_TO"),
        editor_group_format=os.getenv("OIDC_EDITOR_GROUP_FORMAT", "").strip(),
        reader_group_format=os.getenv("OIDC_READER_GROUP_FORMAT", "").strip(),
    )
