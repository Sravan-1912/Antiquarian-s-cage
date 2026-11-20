"""Break-glass password recovery: `python -m app.recover <email>`

Run on the server by whoever controls it (the same trust level as database access). Sets a single-use temporary
password for the named account — the ultimate way back in when a Super Admin is locked out and no other admin can
reset them. The account must change the password on next sign-in.

It prints the temporary password; it never emails. Keep this to the host.
"""
from __future__ import annotations

import sys

from sqlalchemy import func, select

from app.core.database import session_factory
from app.models import User
from app.services import auth


def main(email_addr: str) -> int:
    email_addr = email_addr.strip().lower()
    with session_factory()() as db:
        user = db.scalar(select(User).where(func.lower(User.email) == email_addr))
        if user is None:
            print(f"No account found for {email_addr!r}.", file=sys.stderr)
            return 1
        if user.status == "disabled":
            print(f"{email_addr} is disabled; re-enable it first.", file=sys.stderr)
            return 1
        temp = auth.set_temporary_password(db, user)
        auth.revoke_user_sessions(db, user.id, "break_glass_recovery")
        from app.services import audit
        audit.record(db, user.organization_id, auth.Actor("system", None, "break-glass", None),
                     "user.password_reset", target_type="user", target_id=user.id, target_label=user.email,
                     metadata={"method": "break_glass_cli"})
        db.commit()
    print(f"Break-glass temporary password for {email_addr} (single use — must be changed on next sign-in):")
    print(f"\n    {temp}\n")
    print("Sign in with it at the console; you will be prompted to set a new password.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
