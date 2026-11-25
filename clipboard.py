"""macOS clipboard access, conditional clearing, and copy-failure cleanup."""

import hashlib
import os
import subprocess
import threading

import audit
import security


CLIPBOARD_SECONDS = 20


class Clipboard:
    """Track last copy without retaining another plaintext password."""

    def __init__(self, owner_id: int | None = None):
        """Initialize clipboard tracking and synchronization for the timer."""
        self.owner_id = owner_id
        self.digest = None
        self.timer = None
        # Copy may call clear while holding the lock; timers still serialize here.
        self.mutex = threading.RLock()
        self.warning = ""
        self.generation = 0

    def copy(self, password: str):
        """Copy a password to macOS and schedule conditional clearing."""
        data = bytearray(password, "utf-8")
        password = None
        try:
            with self.mutex:
                # Finish tracking any previous copy before replacing its fingerprint.
                if self.digest is not None:
                    self.clear()
                    if self.digest is not None:
                        raise ValueError("Could not clear the previous password. Clear the clipboard manually and try again.")
                self.digest = hashlib.sha256(data).digest()
                self.warning = ""
                self.generation += 1
                self.timer = threading.Timer(CLIPBOARD_SECONDS, self.clear, args=(self.generation,))
                self.timer.daemon = True
                self.timer.start()
                try:
                    subprocess.run(
                        ["/usr/bin/pbcopy"], input=data, capture_output=True,
                        env={**os.environ, "LC_ALL": "en_US.UTF-8"},
                        check=True, timeout=3,
                    )
                except (OSError, subprocess.SubprocessError):
                    audit.log_event("operation_failed", user_id=self.owner_id, operation="clipboard_copy")
                    # pbcopy may have written the password before reporting failure.
                    self.clear()
                    raise ValueError("Could not copy the password. Clear the clipboard manually if needed.") from None

        finally:
            security.wipe_buffer(data)

    def clear(self, generation=None):
        """Clear our copied password if unchanged, ignoring outdated timers."""
        # Serialize copying and clearing so an old timer cannot clear a new copy.
        with self.mutex:
            if generation is not None and generation != self.generation:
                return
            self.generation += 1
            if self.timer is not None:
                self.timer.cancel()
                self.timer = None
            if self.digest is None:
                return
            try:
                current = subprocess.run(
                    ["/usr/bin/pbpaste", "-Prefer", "txt"], capture_output=True,
                    env={**os.environ, "LC_ALL": "en_US.UTF-8"},
                    check=True, timeout=3,
                ).stdout
                if hashlib.sha256(current).digest() == self.digest:
                    subprocess.run(
                        ["/usr/bin/pbcopy"], input=b"", capture_output=True,
                        check=True, timeout=3,
                    )
            except (OSError, subprocess.SubprocessError):
                audit.log_event("operation_failed", user_id=self.owner_id, operation="clipboard_clear")
                self.warning = "Could not clear the clipboard. Clear it manually."
                return
            self.digest = None
            self.warning = ""
