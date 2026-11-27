"""Authenticated session lifetime and safe terminal interaction."""

from contextlib import contextmanager
import getpass
import math
import signal
import sys
import termios
import time
import warnings

from cryptography.fernet import Fernet

import audit
import clipboard
import security


IDLE_SECONDS = 5 * 60
INACTIVITY_MESSAGE = "Vault locked after five minutes of inactivity."
LOGIN_ATTEMPTS = 3
LOGIN_COOLDOWN_SECONDS = 30


class LoginCooldown:
    """Limit login attempts across menus for this application run only."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.failures = 0
        self.deadline = 0

    def remaining_seconds(self) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining > 0:
            return math.ceil(remaining)
        if self.deadline:
            self.reset()
        return 0

    def record_failure(self):
        self.failures += 1
        if self.failures == LOGIN_ATTEMPTS:
            self.deadline = time.monotonic() + LOGIN_COOLDOWN_SECONDS


class SessionExpired(Exception):
    """Interrupt an idle vault, including a blocked terminal prompt."""


class Session:
    """Keep the authenticated account and its temporary encryption object."""

    def __init__(self, owner_id: int, cipher: Fernet, username: str = ""):
        """Start an unlocked session with its own clipboard tracker."""
        security.validate_owner_id(owner_id)
        self.owner_id = owner_id
        self.username = username
        self.cipher = cipher
        self.clipboard = clipboard.Clipboard(owner_id)
        self.deadline = time.monotonic() + IDLE_SECONDS

    def require_unlocked(self):
        """Reject expired sessions even when called outside the terminal menu."""
        if self.cipher is None:
            raise ValueError("Vault is locked. Log in again.")
        if time.monotonic() >= self.deadline:
            self.lock(reason="inactivity")
            raise SessionExpired(INACTIVITY_MESSAGE)

    def read_input(self, prompt: str, *, hidden=False) -> str:
        """Interrupt only terminal input; never interrupt a vault write or copy."""
        self.require_unlocked()

        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SessionExpired(INACTIVITY_MESSAGE)
        try:
            # terminal_mode owns the signal handler; only input arms the timer.
            signal.setitimer(signal.ITIMER_REAL, remaining)
            value = read_password(prompt) if hidden else input(prompt)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

        self.require_unlocked()
        self.deadline = time.monotonic() + IDLE_SECONDS
        return value

    def lock(self, reason: str = "logout"):
        """Drop the encryption object and attempt to clear our clipboard copy."""
        # Release the encryption object; this does not guarantee memory erasure.
        was_unlocked = self.cipher is not None
        self.cipher = None
        self.clipboard.clear()
        if was_unlocked:
            audit.log_event("vault_locked", user_id=self.owner_id, reason=reason)


def read_password(prompt: str) -> str:
    """Read hidden input, failing if the terminal cannot suppress echo."""
    # Refuse getpass's fallback to visible input if the terminal cannot hide it.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def interrupt_exit(signum, frame):
    """Unwind input so normal finally blocks restore the terminal and lock."""
    if signum == signal.SIGALRM:
        raise SessionExpired(INACTIVITY_MESSAGE)
    raise KeyboardInterrupt


@contextmanager
def terminal_mode():
    """Disable flow control and restore terminal settings and handlers on exit."""
    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    settings = original[:]
    settings[0] &= ~(termios.IXON | termios.IXOFF)
    previous_handlers = {}
    try:
        for signum in (signal.SIGTSTP, signal.SIGQUIT, signal.SIGALRM):
            previous_handlers[signum] = signal.signal(signum, interrupt_exit)
        termios.tcsetattr(descriptor, termios.TCSANOW, settings)
        yield
    finally:
        try:
            # Discard unfinished input and restore echo even after interrupted getpass.
            signal.setitimer(signal.ITIMER_REAL, 0)
            termios.tcsetattr(descriptor, termios.TCSAFLUSH, original)
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
