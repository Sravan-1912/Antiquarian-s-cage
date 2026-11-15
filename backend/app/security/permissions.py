"""Permission catalogue and built-in role definitions.

Roles are persisted in the database (roles / role_permissions) and synchronised from this catalogue at
startup, so the backend is the single source of truth for authorization decisions.
"""
from __future__ import annotations

PERMISSIONS: dict[str, str] = {
    "dashboard:read": "View the operational dashboard",
    "users:read": "View administrator accounts",
    "users:manage": "Invite, disable and assign roles to administrators",
    "employees:read": "View employees",
    "employees:write": "Create and edit employees",
    "employees:lifecycle": "Suspend, reactivate and offboard employees",
    "devices:read": "View all endpoints",
    "devices:read_assigned": "View endpoints assigned to the support engineer",
    "devices:manage": "Suspend, reactivate, revoke and unenrol endpoints",
    "devices:remote": "Initiate authorised remote operations",
    "policies:read": "View security policies",
    "policies:write": "Create, modify, assign and revoke security policies",
    "compliance:read": "View compliance posture",
    "alerts:read": "View security alerts",
    "alerts:manage": "Assign, investigate and resolve alerts",
    "applications:read": "View registered applications",
    "applications:manage": "Register applications and manage access",
    "audit:read": "View the administrative audit log",
    "audit:verify": "Run audit-chain integrity verification",
    "reports:read": "View reports",
    "reports:export": "Export reports as CSV/PDF",
    "org:settings": "Configure organisation settings",
    "self:read": "View own devices, applications and authentication settings",
    "tenant:global": "See every admin's users and endpoints across the organisation (Super Admin only)",
}

ALL = set(PERMISSIONS)

ROLES: dict[str, dict] = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full access, including administrator management and audit logs.",
        "permissions": ALL,
    },
    "admin": {
        "name": "Admin",
        "description": "Manages employees, endpoints, policies and application access.",
        "permissions": {
            "dashboard:read", "users:read", "employees:read", "employees:write", "employees:lifecycle",
            "devices:read", "devices:manage", "devices:remote", "policies:read", "policies:write",
            "compliance:read", "alerts:read", "applications:read", "applications:manage",
            "reports:read", "reports:export", "self:read",
        },
    },
    "security_analyst": {
        "name": "Security Analyst",
        "description": "Investigates alerts and reviews posture and compliance.",
        "permissions": {
            "dashboard:read", "employees:read", "devices:read", "policies:read", "compliance:read",
            "alerts:read", "alerts:manage", "reports:read", "reports:export", "self:read",
        },
    },
    "it_support": {
        "name": "IT Support",
        "description": "Troubleshoots assigned endpoints and performs approved remote assistance.",
        "permissions": {"dashboard:read", "employees:read", "devices:read_assigned", "devices:remote", "self:read"},
    },
    "employee": {
        "name": "Employee",
        "description": "Self-service access to own devices, applications and authentication settings.",
        "permissions": {"self:read"},
    },
}

# Roles an administrator may grant. Only super admins may grant super_admin.
PRIVILEGED_ROLE = "super_admin"
