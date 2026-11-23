"""Real macOS terminal checks, isolated from the unit tests."""

import errno
import os
import pty
import select
import signal
import sys
import time
import unittest


@unittest.skipUnless(sys.platform == "darwin", "macOS terminal integration")
class TerminalTests(unittest.TestCase):
    def run_terminal(self, script, responses=()):
        """Run a child terminal and send each response after its prompt appears."""
        pid, descriptor = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, "-c", script])
        output = b""
        exited = False
        responses = iter(responses)
        pending = next(responses, None)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if select.select([descriptor], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(descriptor, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output += chunk
                    if pending and pending[0] in output:
                        os.write(descriptor, pending[1])
                        pending = next(responses, None)
            while time.monotonic() < deadline:
                child, status = os.waitpid(pid, os.WNOHANG)
                if child == pid:
                    exited = True
                    break
                time.sleep(0.01)
            self.assertTrue(exited, output.decode(errors="replace"))
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors="replace"))
            self.assertIn(b"CLEANUP_OK", output)
            self.assertNotIn(b"Traceback", output)
            return output
        finally:
            os.close(descriptor)
            if not exited:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_real_alarm_interrupts_visible_and_hidden_terminal_prompts(self):
        for hidden in [False, True]:
            with self.subTest(hidden=hidden):
                self.run_terminal(f'''
import termios
import passwdmanager as pm
pm.IDLE_SECONDS = 0.05
session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
before = termios.tcgetattr(0)
try:
    session.read_input("Waiting: ", hidden={hidden!r})
except pm.SessionExpired:
    session.lock()
    assert session.cipher is None
    assert termios.tcgetattr(0) == before, "terminal settings were not restored"
    assert pm.signal.getitimer(pm.signal.ITIMER_REAL) == (0.0, 0.0)
    print("CLEANUP_OK", flush=True)
else:
    raise AssertionError("Input unexpectedly returned")
''')

    def test_control_keys_exit_and_restore_visible_and_hidden_prompts(self):
        for hidden in [False, True]:
            for key in [b"\x03", b"\x04", b"\x1a", b"\x1c", b"\x19"]:  # interrupt, EOF, suspend, quit, delayed suspend
                with self.subTest(hidden=hidden, key=key):
                    responses = [(b"Choice: ", b"1\n"), (b"Hidden: ", key + b"\n" if key == b"\x19" else key)] if hidden else [(b"Choice: ", key + b"\n" if key == b"\x19" else key)]
                    self.run_terminal(f'''
import signal
import termios
from unittest.mock import Mock
import passwdmanager as pm
session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
session.clipboard = Mock(warning="")
def hidden_prompt(database, session):
    session.read_input("Hidden: ", hidden=True)
pm.prompt_add_entry = hidden_prompt
settings = termios.tcgetattr(0)
settings[6][termios.VDSUSP] = b"\\x19"
termios.tcsetattr(0, termios.TCSANOW, settings)
before = termios.tcgetattr(0)
try:
    with pm.terminal_mode():
        pm.run_vault(None, session)
except (EOFError, KeyboardInterrupt):
    pass
else:
    raise AssertionError("Control key did not exit")
assert session.cipher is None
session.clipboard.clear.assert_called_once_with()
assert termios.tcgetattr(0) == before, "terminal settings were not restored"
assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
print("CLEANUP_OK", flush=True)
''', responses)

    def test_flow_control_cannot_pause_output_and_settings_are_restored(self):
        for hidden in [False, True]:
            with self.subTest(hidden=hidden):
                self.run_terminal(f'''
import termios
import passwdmanager as pm
original = termios.tcgetattr(0)
original[0] |= termios.IXON | termios.IXOFF
termios.tcsetattr(0, termios.TCSANOW, original)
session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
with pm.terminal_mode():
    assert not termios.tcgetattr(0)[0] & (termios.IXON | termios.IXOFF)
    session.read_input("Flow: ", hidden={hidden!r})
    print("OUTPUT_CONTINUES", flush=True)
assert termios.tcgetattr(0) == original
print("CLEANUP_OK", flush=True)
''', [(b"Flow: ", b"\x13\x11\n")])

    def test_hidden_line_editing_does_not_echo_secrets(self):
        cases = [
            (b"hidden-secretX\x7f\n", "hidden-secret"),
            (b"hidden-secret\x15replacement\n", "replacement"),
            (b"hidden-secret word\x17\n", "hidden-secret "),
            (b"hidden-secret\x12\n", "hidden-secret"),
            (b"hidden-secret\x16\x03\n", "hidden-secret\x03"),
        ]
        for typed, expected in cases:
            with self.subTest(typed=typed):
                output = self.run_terminal(f'''
import termios
import passwdmanager as pm
original = termios.tcgetattr(0)
with pm.terminal_mode():
    value = pm.read_password("Secret: ")
    assert value == {expected!r}, "Unexpected editing result"
assert termios.tcgetattr(0) == original
print("CLEANUP_OK", flush=True)
''', [(b"Secret: ", typed)])
                self.assertNotIn(b"hidden-secret", output)
                self.assertNotIn(b"replacement", output)

    def test_partial_input_eof_is_validated_as_ordinary_input(self):
        for hidden in [False, True]:
            with self.subTest(hidden=hidden):
                self.run_terminal(f'''
import termios
import passwdmanager as pm
original = termios.tcgetattr(0)
session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
with pm.terminal_mode():
    value = session.read_input("Partial: ", hidden={hidden!r})
    assert value == "abc", "Partial input was changed"
    try:
        pm.validate_master_password(value)
    except ValueError:
        pass
    else:
        raise AssertionError("Short password accepted")
assert termios.tcgetattr(0) == original
session.lock()
print("CLEANUP_OK", flush=True)
''', [(b"Partial: ", b"abc\x04\n")])


if __name__ == "__main__":
    unittest.main()
