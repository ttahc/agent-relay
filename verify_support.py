"""Shared helpers for the verify*.py checks (not a check itself)."""
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent

# A disposable project nests "<prefix><random>/.state/<store>/upgrade-control.sock"
# under its parent. pool.lifecycle.Control refuses socket paths over 100 bytes
# (the AF_UNIX limit is about 108), so keep that much room for the tail.
SOCKET_LIMIT = 100
TAIL_RESERVE = 72


def _short_enough(parent, reserve=TAIL_RESERVE):
    return os.name != "posix" or len(os.fsencode(parent)) + reserve <= SOCKET_LIMIT


def _system_temp():
    parent = Path(tempfile.gettempdir())
    return parent if _short_enough(parent) else Path("/tmp")


def scratch(prefix="verify-"):
    """Temporary directory for a disposable project, safe for any checkout path.

    Order: $TASKPOOL_VERIFY_TMP if set, then <repo>/.state (the historical
    location, kept so Windows runs stay on the checkout's own filesystem), and
    on POSIX the system temp folder when <repo>/.state is too long for the
    upgrade-control Unix socket.
    """
    override = os.environ.get("TASKPOOL_VERIFY_TMP")
    if override:
        parent = Path(override)
    else:
        parent = ROOT / ".state"
        if not _short_enough(parent):
            parent = _system_temp()
    parent.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=parent)


def fixture_dir(name):
    """Persistent fixture folder: <repo>/<name>, or the system temp folder on long POSIX paths."""
    override = os.environ.get("TASKPOOL_VERIFY_TMP")
    if override:
        return Path(override) / name
    path = ROOT / name
    return path if _short_enough(path, 48) else _system_temp() / ("taskpool-" + name)


def report_path(name):
    """Default --report location: <repo>/dist/<name>, independent of the cwd."""
    path = ROOT / "dist" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


if __name__ == "__main__":
    print(__doc__)
