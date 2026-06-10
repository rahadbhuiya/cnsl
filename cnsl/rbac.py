"""
cnsl/rbac.py — Role-Based Access Control.

Roles (least to most privileged):
  viewer   — read-only: stats, incidents, blocks list
  analyst  — viewer + manual block/unblock + view FIM alerts
  auditor  — analyst + generate reports + view all logs
  admin    — full access including config, user management

Permission table:
  Permission              viewer  analyst  auditor  admin
  ─────────────────────── ─────── ──────── ──────── ─────
  stats_read              ✓       ✓        ✓        ✓
  incidents_read          ✓       ✓        ✓        ✓
  blocks_read             ✓       ✓        ✓        ✓
  top_attackers_read      ✓       ✓        ✓        ✓
  metrics_read            ✓       ✓        ✓        ✓
  fim_read                        ✓        ✓        ✓
  block_write                     ✓        ✓        ✓
  unblock_write                   ✓        ✓        ✓
  report_generate                          ✓        ✓
  logs_read                                ✓        ✓
  asset_read                               ✓        ✓
  config_read                                       ✓
  config_write                                      ✓
  user_manage                                       ✓
  honeypot_manage                                   ✓
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Set



# Permission constants


class Perm:
    # Read permissions
    STATS_READ          = "stats:read"
    INCIDENTS_READ      = "incidents:read"
    BLOCKS_READ         = "blocks:read"
    TOP_ATTACKERS_READ  = "top_attackers:read"
    METRICS_READ        = "metrics:read"
    FIM_READ            = "fim:read"
    LOGS_READ           = "logs:read"
    ASSET_READ          = "asset:read"
    CONFIG_READ         = "config:read"

    # Write permissions
    BLOCK_WRITE         = "block:write"
    UNBLOCK_WRITE       = "unblock:write"
    REPORT_GENERATE     = "report:generate"
    CONFIG_WRITE        = "config:write"
    USER_MANAGE         = "user:manage"
    HONEYPOT_MANAGE     = "honeypot:manage"



# Role definitions


_VIEWER_PERMS: FrozenSet[str] = frozenset({
    Perm.STATS_READ,
    Perm.INCIDENTS_READ,
    Perm.BLOCKS_READ,
    Perm.TOP_ATTACKERS_READ,
    Perm.METRICS_READ,
})

_ANALYST_PERMS: FrozenSet[str] = _VIEWER_PERMS | frozenset({
    Perm.FIM_READ,
    Perm.BLOCK_WRITE,
    Perm.UNBLOCK_WRITE,
})

_AUDITOR_PERMS: FrozenSet[str] = _ANALYST_PERMS | frozenset({
    Perm.REPORT_GENERATE,
    Perm.LOGS_READ,
    Perm.ASSET_READ,
})

_ADMIN_PERMS: FrozenSet[str] = _AUDITOR_PERMS | frozenset({
    Perm.CONFIG_READ,
    Perm.CONFIG_WRITE,
    Perm.USER_MANAGE,
    Perm.HONEYPOT_MANAGE,
})

ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "viewer":  _VIEWER_PERMS,
    "analyst": _ANALYST_PERMS,
    "auditor": _AUDITOR_PERMS,
    "admin":   _ADMIN_PERMS,
}

VALID_ROLES: Set[str] = set(ROLE_PERMISSIONS.keys())



# RBAC checker


class RBAC:
    """
    Checks permissions for a given role.

    Usage:
        rbac = RBAC()
        if rbac.can(role="analyst", perm=Perm.BLOCK_WRITE):
            await blocker.block_ip(...)
        else:
            return 403
    """

    def can(self, role: str, perm: str) -> bool:
        """Return True if role has the given permission."""
        perms = ROLE_PERMISSIONS.get(role, frozenset())
        return perm in perms

    def permissions(self, role: str) -> FrozenSet[str]:
        """Return all permissions for a role."""
        return ROLE_PERMISSIONS.get(role, frozenset())

    def role_info(self) -> Dict:
        """Return role hierarchy info (for dashboard display)."""
        return {
            role: sorted(perms)
            for role, perms in ROLE_PERMISSIONS.items()
        }

    def require(self, role: str, perm: str) -> Optional[Dict]:
        """
        Returns None if allowed, or a 403 error dict if denied.
        Used as a guard in API handlers:
            if err := rbac.require(user_role, Perm.BLOCK_WRITE):
                return web.json_response(err, status=403)
        """
        if self.can(role, perm):
            return None
        return {
            "error":      "Forbidden",
            "required":   perm,
            "your_role":  role,
            "hint":       f"This action requires the '{_min_role(perm)}' role or higher.",
        }


def _min_role(perm: str) -> str:
    """Return the minimum role needed for a permission."""
    for role in ("viewer", "analyst", "auditor", "admin"):
        if perm in ROLE_PERMISSIONS[role]:
            return role
    return "admin"