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
            for key in [b"\x03", b"\x04", b"\x1a"]:  # Ctrl-C, Ctrl-D, Ctrl-Z
                with self.subTest(hidden=hidden, key=key):
                    responses = [(b"Choice: ", b"1\n"), (b"Hidden: ", key)] if hidden else [(b"Choice: ", key)]
                    self.run_terminal(f'''
import signal
import termios
from unittest.mock import Mock
import passwdmanager as pm
signal.signal(signal.SIGTSTP, pm.interrupt_exit)
session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
session.clipboard = Mock(warning="")
def hidden_prompt(database, session):
    session.read_input("Hidden: ", hidden=True)
pm.prompt_add_entry = hidden_prompt
before = termios.tcgetattr(0)
try:
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


if __name__ == "__main__":
    unittest.main()
