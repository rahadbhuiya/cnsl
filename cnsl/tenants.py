"""
cnsl/tenants.py — Multi-tenant support.

Allows a single CNSL instance to serve multiple isolated organizations
(tenants). Each tenant has:
  - Independent user accounts and roles
  - Isolated incidents, cases, blocks, UEBA profiles
  - Per-tenant alert rules (override global defaults)
  - Per-tenant notification channels
  - Per-tenant allowlist and country_block config
  - Scoped dashboard API access (JWT includes tenant_id claim)

Tenant isolation model:
  - Shared: detection engine, GeoIP, threat feed, log sources
  - Isolated: incidents DB rows (tenant_id column), cases, blocks,
    UEBA profiles, notification config, rule overrides

Config (config.json):
  "tenants": {
    "enabled": true,
    "default_tenant": "default",
    "list": {
      "acme": {
        "display_name": "Acme Corp",
        "users": {
          "admin": {"password_hash": "...", "role": "admin"}
        },
        "notifications": { ... },
        "rules": { "ssh.brute_force": {"threshold": 3} },
        "allowlist": ["10.0.0.0/8"],
        "country_block": {"enabled": false, "countries": []}
      },
      "globex": {
        "display_name": "Globex Inc",
        "users": { ... }
      }
    }
  }

When tenants.enabled is false, CNSL runs in single-tenant mode (default).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from .rules import RuleEngine


#  Tenant dataclass 


class Tenant:
    """
    Represents a single tenant with isolated config and rule overrides.
    """

    def __init__(self, tenant_id: str, cfg: Dict[str, Any]):
        self.id           = tenant_id
        self.display_name = cfg.get("display_name", tenant_id)
        self.users:  Dict[str, Any]  = cfg.get("users", {})
        self.notifications: Dict     = cfg.get("notifications", {})
        self.allowlist: List[str]    = cfg.get("allowlist", [])
        self.country_block: Dict     = cfg.get("country_block", {})
        self.rules_cfg: Dict         = cfg.get("rules", {})

        # Per-tenant RuleEngine (inherits global defaults, then overlays)
        self._rules: Optional[RuleEngine] = None

    def get_rules(self, global_cfg: Dict[str, Any]) -> RuleEngine:
        """
        Get the per-tenant RuleEngine.
        Merges global rules config with tenant-specific overrides.
        Cached after first call.
        """
        if self._rules is None:
            merged = copy.deepcopy(global_cfg)
            tenant_rules = merged.setdefault("rules", {})
            tenant_rules.update(self.rules_cfg)
            self._rules = RuleEngine(merged)
        return self._rules

    def invalidate_rules_cache(self) -> None:
        """Force RuleEngine rebuild on next get_rules() call."""
        self._rules = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":           self.id,
            "display_name": self.display_name,
            "user_count":   len(self.users),
            "has_custom_rules": bool(self.rules_cfg),
            "has_custom_notifications": bool(self.notifications),
            "allowlist_count": len(self.allowlist),
            "country_block_enabled": bool(
                self.country_block.get("enabled") and
                self.country_block.get("countries")
            ),
        }


#  TenantManager 


class TenantManager:
    """
    Manages tenant registry, resolution, and JWT tenant claims.

    Single-tenant mode (tenants.enabled = false):
      - A single synthetic "default" tenant wraps the root config.
      - All existing behaviour is preserved unchanged.

    Multi-tenant mode:
      - Each tenant has isolated users, rules, notifications, allowlist.
      - JWT tokens include {"tenant_id": "acme"} claim.
      - API routes filter incidents/cases/blocks by tenant_id.
    """

    def __init__(self, cfg: Dict[str, Any]):
        tc = cfg.get("tenants", {})
        self.enabled         = bool(tc.get("enabled", False))
        self.default_tenant  = tc.get("default_tenant", "default")
        self._global_cfg     = cfg
        self._tenants: Dict[str, Tenant] = {}

        if self.enabled:
            for tid, tcfg in tc.get("list", {}).items():
                self._tenants[tid] = Tenant(tid, tcfg)
        else:
            # Single-tenant: synthetic default tenant from root config
            self._tenants[self.default_tenant] = Tenant(
                self.default_tenant,
                {
                    "display_name":  "Default",
                    "users":         cfg.get("auth", {}).get("users", {}),
                    "notifications": cfg.get("notifications", {}),
                    "allowlist":     cfg.get("allowlist", []),
                    "country_block": cfg.get("country_block", {}),
                    "rules":         cfg.get("rules", {}),
                },
            )

    #  Tenant resolution 

    def get(self, tenant_id: str) -> Optional[Tenant]:
        return self._tenants.get(tenant_id)

    def get_default(self) -> Tenant:
        return self._tenants[self.default_tenant]

    def resolve(self, tenant_id: Optional[str]) -> Tenant:
        """Return tenant by id, falling back to default."""
        if tenant_id and tenant_id in self._tenants:
            return self._tenants[tenant_id]
        return self.get_default()

    def list_tenants(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._tenants.values()]

    @property
    def count(self) -> int:
        return len(self._tenants)

    #  User resolution 

    def get_user(self, username: str, tenant_id: Optional[str] = None) -> Optional[Dict]:
        """
        Look up a user in the specified tenant (or all tenants in single-tenant mode).
        Returns (user_dict, tenant_id) or None.
        """
        tenant = self.resolve(tenant_id)
        user   = tenant.users.get(username)
        if user:
            return user
        # In multi-tenant mode, also search all tenants for global admins
        if self.enabled:
            for t in self._tenants.values():
                u = t.users.get(username)
                if u and u.get("role") == "admin" and u.get("global"):
                    return u
        return None

    #  Per-tenant rule engine 

    def get_rules(self, tenant_id: Optional[str] = None) -> RuleEngine:
        """Get the RuleEngine for a tenant (with per-tenant overrides applied)."""
        tenant = self.resolve(tenant_id)
        return tenant.get_rules(self._global_cfg)

    #  Admin operations 

    def add_tenant(self, tenant_id: str, cfg: Dict[str, Any]) -> Optional[str]:
        """Add a new tenant. Returns None on success, error string on failure."""
        if not self.enabled:
            return "Multi-tenant mode is not enabled."
        if tenant_id in self._tenants:
            return f"Tenant '{tenant_id}' already exists."
        if not tenant_id or not tenant_id.replace("-", "").replace("_", "").isalnum():
            return "Tenant ID must be alphanumeric (dashes and underscores allowed)."
        self._tenants[tenant_id] = Tenant(tenant_id, cfg)
        return None

    def remove_tenant(self, tenant_id: str) -> Optional[str]:
        """Remove a tenant. Cannot remove the default tenant."""
        if tenant_id == self.default_tenant:
            return f"Cannot remove the default tenant '{self.default_tenant}'."
        if tenant_id not in self._tenants:
            return f"Tenant '{tenant_id}' not found."
        del self._tenants[tenant_id]
        return None

    def update_tenant_rules(
        self, tenant_id: str, rule_updates: Dict[str, Any]
    ) -> Optional[str]:
        """Apply rule overrides to a specific tenant's RuleEngine."""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return f"Tenant '{tenant_id}' not found."
        tenant.rules_cfg.update(rule_updates)
        tenant.invalidate_rules_cache()
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "enabled":        self.enabled,
            "tenant_count":   self.count,
            "default_tenant": self.default_tenant,
            "tenants":        self.list_tenants(),
        }