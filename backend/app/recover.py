"""Break-glass passkey recovery: `python -m app.recover <email>`

Run on the server by whoever controls it (the same trust level as database access). Mints a single-use, 1-hour
recovery link so the named account can register a fresh passkey, even if every passkey is lost and no other admin
can issue recovery. This is the ultimate way back in under admin-issued-only recovery — keep it to the host.

It prints the link; it never emails. Open the link in a browser to complete the passkey registration.
"""
from __future__ import annotations

import sys

from sqlalchemy import func, select

from app.core.database import session_factory
from app.models import User
from app.services import auth
from app.services.email import link as email_link


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
        raw = auth.issue_recovery(db, user)
        from app.services import audit
        audit.record(db, user.organization_id, auth.Actor("system", None, "break-glass", None),
                     "user.recovery_issued", target_type="user", target_id=user.id, target_label=user.email,
                     metadata={"method": "break_glass_cli"})
        db.commit()
    url = email_link("/recover", raw)  # already an absolute URL (PUBLIC_BASE_URL + path)
    print("Break-glass recovery link (valid 1 hour, single use):")
    print(url)
    print("\nOpen it in a browser and register a new passkey. All existing passkeys for this account are revoked "
          "when the new one is enrolled.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
