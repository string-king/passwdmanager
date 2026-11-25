"""Structured audit events and private file creation.

Credential contents must never be passed to log_event.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import stat
import sys


LOG_FILE = Path(__file__).resolve().parent / "logs" / "events.jsonl"
LOGGER = logging.getLogger("passwdmanager.events")
LOGGER.addHandler(logging.NullHandler())
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


class EventLogHandler(logging.StreamHandler):
    def handleError(self, record):
        # Never print logging internals or the original exception to the terminal.
        print("Could not write the security log. Check permissions and disk space.", file=sys.stderr)


def private_directory(path: Path):
    """Reject symlinked application directories before changing permissions."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise OSError("Unsafe application directory.")
    path.chmod(0o700)


def open_private_file(path: Path, flags: int) -> int:
    """Open a regular private file; nonblocking mode prevents FIFO hangs."""
    private_directory(path.parent)
    descriptor = os.open(path, flags | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("Expected a regular file.")
        os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def configure_logging(path: Path = LOG_FILE):
    """Open one private append-only JSON Lines file for this process."""
    descriptor = open_private_file(path, os.O_APPEND | os.O_WRONLY)
    try:
        stream = os.fdopen(descriptor, "a", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    handler = EventLogHandler(stream)
    LOGGER.addHandler(handler)
    return handler


def log_event(event: str, *, user_id: int | None = None,
              operation: str | None = None, reason: str | None = None):
    """Accept only explicit audit fields; callers never pass credential contents."""
    level = logging.WARNING if event in ("login_failed", "integrity_check_failed", "operation_failed") else logging.INFO
    record = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "severity": logging.getLevelName(level), "event": event}
    if user_id is not None:
        record["user_id"] = user_id
    if operation is not None:
        record["operation"] = operation
    if reason is not None:
        record["reason"] = reason
    LOGGER.log(level, json.dumps(record))
