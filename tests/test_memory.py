"""Check cleanup of buffers and references we control, not whole-process erasure."""

import subprocess
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm


class MemoryTests(unittest.TestCase):
    def test_wipe_overwrites_existing_buffer_in_place(self):
        secret = bytearray("secret õ", "utf-8")
        view = memoryview(secret)
        pm.wipe_buffer(secret)
        self.assertEqual(bytes(view), b"\x00" * len(secret))
        pm.wipe_buffer(secret)
        pm.wipe_buffer(bytearray())

    def test_registration_wipes_kdf_input_on_success_and_failure(self):
        for failure in [False, True]:
            with self.subTest(failure=failure):
                captured = []
                def derive(buffer):
                    captured.append(buffer)
                    self.assertEqual(buffer, b"master password")
                    if failure:
                        raise RuntimeError("KDF failed")
                    return b"v" * 32
                kdf = Mock()
                kdf.derive.side_effect = derive
                database = Mock()
                database.execute.return_value.lastrowid = 1
                database.__enter__ = Mock(return_value=database)
                database.__exit__ = Mock(return_value=False)
                with patch.object(pm, "password_kdf", return_value=kdf):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            pm.register_account(database, "alice", "master password")
                    else:
                        pm.register_account(database, "alice", "master password")
                self.assertEqual(captured[0], bytearray(len(captured[0])))

    def test_login_reuses_and_wipes_password_buffer_on_all_kdf_paths(self):
        for failure in [None, "verify", "derive"]:
            with self.subTest(failure=failure):
                captured = []
                def verify(buffer, verifier):
                    captured.append(buffer)
                    self.assertEqual(buffer, b"master password")
                    if failure == "verify":
                        raise pm.InvalidKey
                def derive(buffer):
                    captured.append(buffer)
                    self.assertIs(buffer, captured[0])
                    self.assertEqual(buffer, b"master password")
                    if failure == "derive":
                        raise RuntimeError("KDF failed")
                    return b"k" * 32
                kdf = Mock()
                kdf.verify.side_effect = verify
                kdf.derive.side_effect = derive
                database = Mock()
                database.execute.return_value.fetchone.return_value = dict(
                    id=1, iterations=pm.KDF_ITERATIONS, lanes=pm.KDF_LANES,
                    memory_cost=pm.KDF_MEMORY_COST, verifier=b"v" * 32,
                    verification_salt=b"s" * 16, key_salt=b"t" * 16)
                with patch.object(pm, "password_kdf", return_value=kdf):
                    if failure:
                        with self.assertRaises(ValueError if failure == "verify" else RuntimeError):
                            pm.login_account(database, "alice", "master password")
                    else:
                        session = pm.login_account(database, "alice", "master password")
                        session.lock()
                self.assertTrue(captured)
                self.assertTrue(all(buffer == bytearray(len(buffer)) for buffer in captured))

    def test_clipboard_buffer_is_wiped_after_success_or_failure(self):
        for failure in [False, True]:
            with self.subTest(failure=failure):
                captured = []
                def copy(command, **kwargs):
                    captured.append(kwargs["input"])
                    self.assertEqual(kwargs["input"], b"secret")
                    if failure:
                        raise OSError("clipboard failed")
                    return subprocess.CompletedProcess(command, 0)
                clipboard = pm.Clipboard()
                with patch.object(pm.subprocess, "run", side_effect=copy), patch.object(pm.threading, "Timer"):
                    if failure:
                        with self.assertRaises(ValueError):
                            clipboard.copy("secret")
                    else:
                        clipboard.copy("secret")
                self.assertEqual(captured[0], bytearray(6))

    def test_copy_releases_entry_fields_even_when_clipboard_fails(self):
        for failure in [False, True]:
            with self.subTest(failure=failure):
                entry = {"password": "secret"}
                session = Mock(owner_id=1)
                if failure:
                    session.clipboard.copy.side_effect = ValueError("copy failed")
                with patch.object(pm, "load_entry", return_value=entry):
                    if failure:
                        with self.assertRaises(ValueError):
                            pm.copy_entry_password(None, session, "id")
                    else:
                        pm.copy_entry_password(None, session, "id")
                self.assertEqual(entry, {})

    def test_listing_clears_each_entry_before_decrypting_next(self):
        session = Mock(owner_id=1)
        database = Mock()
        database.execute.return_value.fetchall.return_value = [{"id": "first"}, {"id": "second"}]
        entries = []
        def decrypt(session, row):
            if entries:
                self.assertEqual(entries[-1], {})
            entry = dict(service="site", username="user", password="secret", updated_at=None)
            entries.append(entry)
            return entry
        with patch.object(pm, "decrypt_entry", side_effect=decrypt):
            summaries = pm.list_entries(database, session)
        self.assertTrue(all(entry == {} for entry in entries))
        self.assertTrue(all("password" not in summary for summary in summaries))

    def test_failed_encryption_clears_plaintext_entry(self):
        session = Mock(owner_id=1)
        entry = dict(id="id", owner_id=1, service="site", username="user", password="secret")
        session.cipher.encrypt.side_effect = RuntimeError("encryption failed")
        with patch.object(pm, "load_entry", return_value=entry):
            with self.assertRaises(RuntimeError):
                pm.update_entry(None, session, "id", "new site", "user")
        self.assertEqual(entry, {})


if __name__ == "__main__":
    unittest.main()
