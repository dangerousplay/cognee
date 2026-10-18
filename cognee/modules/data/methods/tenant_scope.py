from cognee.modules.users.authentication.oidc.config import is_oidc_mode


def is_tenant_scoped(user) -> bool:
    """Under AUTH_MODE=oidc a dataset name belongs to the active tenant, not the owner."""
    return is_oidc_mode() and getattr(user, "tenant_id", None) is not None
