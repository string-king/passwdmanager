"""Real macOS terminal checks, isolated from the unit tests."""

import sys
import unittest


class TerminalTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "macOS terminal integration")
    def test_real_alarm_interrupts_visible_and_hidden_terminal_prompts(self):
        import errno
        import os
        import pty
        import select
        import time

        for hidden in [False, True]:
            with self.subTest(hidden=hidden):
                pid, descriptor = pty.fork()
                if pid == 0:
                    script = f'''
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
    print("TIMEOUT_CLEANUP_OK", flush=True)
else:
    raise AssertionError("Input unexpectedly returned")
'''
                    os.execv(sys.executable, [sys.executable, "-c", script])
                output = b""
                exited = False
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
                    child, status = os.waitpid(pid, os.WNOHANG)
                    exited = child == pid
                    self.assertTrue(exited, output.decode(errors="replace"))
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors="replace"))
                    self.assertIn(b"TIMEOUT_CLEANUP_OK", output)
                finally:
                    os.close(descriptor)
                    if not exited:
                        os.kill(pid, pm.signal.SIGKILL)
                        os.waitpid(pid, 0)


if __name__ == "__main__":
    unittest.main()
