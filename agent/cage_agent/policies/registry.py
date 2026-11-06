"""Registry helpers that always capture the previous value so every change can be rolled back exactly."""
from __future__ import annotations

import sys

if sys.platform == "win32":
    import winreg

    HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    TYPES = {"dword": winreg.REG_DWORD, "sz": winreg.REG_SZ}

ABSENT = {"absent": True}


def _split(path: str):
    hive, _, sub = path.partition("\\")
    return HIVES[hive], sub


def read(path: str, name: str) -> dict:
    hive, sub = _split(path)
    try:
        with winreg.OpenKey(hive, sub) as k:
            value, typ = winreg.QueryValueEx(k, name)
            return {"value": value, "type": "dword" if typ == winreg.REG_DWORD else "sz"}
    except FileNotFoundError:
        return dict(ABSENT)


def _exists(path: str) -> bool:
    hive, sub = _split(path)
    try:
        winreg.OpenKey(hive, sub).Close()
        return True
    except FileNotFoundError:
        return False


def _missing_keys(path: str) -> list[str]:
    """Keys (deepest first) that CreateKeyEx would create for `path`."""
    missing = []
    while "\\" in path and not _exists(path):
        missing.append(path)
        path = path.rpartition("\\")[0]
    return missing


def write(path: str, name: str, value, typ: str = "dword") -> dict:
    """Set a value; returns the previous state ({'absent': True} or {'value', 'type'}), plus any keys it had to
    create (`created_keys`, deepest first) so rollback can remove them and leave the registry exactly as found."""
    previous = read(path, name)
    created = _missing_keys(path)
    if created:
        previous["created_keys"] = created
    hive, sub = _split(path)
    with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, TYPES[typ], value)
    return previous


def _delete_if_empty(path: str) -> None:
    hive, sub = _split(path)
    try:
        with winreg.OpenKey(hive, sub) as k:
            subkeys, values, _ = winreg.QueryInfoKey(k)
        if subkeys == 0 and values == 0:
            winreg.DeleteKey(hive, sub)
    except FileNotFoundError:
        pass


def restore(path: str, name: str, previous: dict) -> None:
    hive, sub = _split(path)
    if previous.get("absent"):
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass
        return
    with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, TYPES[previous["type"]], previous["value"])


def apply_values(values: list[tuple[str, str, object, str]]) -> dict:
    """Write several values; on any failure, roll back the ones already written and re-raise."""
    done: list[tuple[str, str, dict]] = []
    try:
        for path, name, value, typ in values:
            done.append((path, name, write(path, name, value, typ)))
    except Exception:
        try:
            restore_values({f"{p}\\{n}": prev for p, n, prev in done})
        except OSError:
            pass
        raise
    return {f"{p}\\{n}": prev for p, n, prev in done}


def restore_values(previous: dict) -> None:
    """Restore every value, then remove keys this policy created — only if they are now empty, so anything another
    tool added meanwhile is never deleted."""
    created: list[str] = []
    for full, prev in previous.items():
        path, _, name = full.rpartition("\\")
        restore(path, name, prev)
        created += prev.get("created_keys", [])
    for key in sorted(set(created), key=lambda k: -k.count("\\")):  # deepest first
        _delete_if_empty(key)
