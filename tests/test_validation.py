"""Malformed data is rejected before use, with controlled errors."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
        self.entry_id = "a" * 32
        self.entry = dict(id=self.entry_id, owner_id=1, service="site", username="user", password="secret")

    def row(self, text):
        return {"id": self.entry_id, "payload": self.session.cipher.encrypt(text.encode())}

    def test_cli_installs_and_restores_suspend_handler_on_interrupt(self):
        previous = pm.signal.getsignal(pm.signal.SIGTSTP)
        handler = Mock()
        database = Mock()
        def interrupted_run(connection):
            self.assertIs(pm.signal.getsignal(pm.signal.SIGTSTP), pm.interrupt_exit)
            pm.interrupt_exit(pm.signal.SIGTSTP, None)
        with patch.object(pm.sys.stdin, "isatty", return_value=True), \
                patch.object(pm.sys.stdout, "isatty", return_value=True), \
                patch.object(pm.termios, "tcgetattr", return_value=[0, 0, 0, 0, 0, 0, []]), \
                patch.object(pm.termios, "tcsetattr"), \
                patch.object(pm, "configure_logging", return_value=handler), \
                patch.object(pm, "open_database", return_value=database), \
                patch.object(pm, "run", side_effect=interrupted_run), patch("builtins.print"):
            self.assertEqual(pm.main(), 0)
        self.assertEqual(pm.signal.getsignal(pm.signal.SIGTSTP), previous)
        database.close.assert_called_once_with()
        handler.stream.close.assert_called_once_with()

    def test_record_id_format(self):
        pm.validate_entry_id(self.entry_id)
        for value in [None, 1, "", "a" * 31, "a" * 33, "A" * 32, "g" * 32, "' OR 1=1 --"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                pm.validate_entry_id(value)

    def test_owner_id_requires_positive_sqlite_integer(self):
        for value in [True, False, "1", 1.0, 0, -1, 2**63, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                pm.validate_owner_id(value)
        pm.validate_owner_id(1)

    def test_invalid_payload_types_and_sizes_are_not_decrypted(self):
        for payload in [None, "text", 123, b"", b"x" * (pm.MAX_PAYLOAD_BYTES + 1)]:
            with self.subTest(kind=type(payload).__name__), patch.object(self.session.cipher, "decrypt") as decrypt:
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    pm.decrypt_entry(self.session, {"id": self.entry_id, "payload": payload})
                decrypt.assert_not_called()

    def test_malformed_duplicate_and_nested_json_have_safe_error(self):
        duplicate = json.dumps(self.entry)[:-1] + ', "password": "other secret"}'
        samples = ["{broken", duplicate, "[" * 1500 + "0" + "]" * 1500,
                   json.dumps({**self.entry, "owner_id": True}),
                   json.dumps({**self.entry, "id": "A" * 32}),
                   json.dumps({**self.entry, "updated_at": []})]
        for text in samples:
            with self.subTest(sample=text[:30]):
                with self.assertRaisesRegex(ValueError, "^Entry integrity check failed. Vault data may be damaged.$"):
                    pm.decrypt_entry(self.session, self.row(text))

    def test_largest_valid_unicode_entry_fits_payload_limit(self):
        entry = {**self.entry, "service": "😀" * 256, "username": "😀" * 256,
                 "password": "😀" * 1024, "updated_at": pm.datetime.now(pm.timezone.utc).isoformat()}
        row = self.row(json.dumps(entry))
        self.assertLess(len(row["payload"]), pm.MAX_PAYLOAD_BYTES)
        self.assertEqual(pm.decrypt_entry(self.session, row)["password"], entry["password"])

    def test_password_invalid_unicode_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid Unicode"):
            pm.validate_password("bad\ud800", "Password")

    def test_bad_account_metadata_rejected_before_kdf(self):
        base = dict(id=1, iterations=pm.KDF_ITERATIONS, lanes=pm.KDF_LANES,
                    memory_cost=pm.KDF_MEMORY_COST, verifier=b"v" * 32,
                    verification_salt=b"s" * 16, key_salt=b"t" * 16)
        for field, value in [("id", 0), ("id", True), ("iterations", float(pm.KDF_ITERATIONS)),
                             ("verification_salt", b"short"), ("key_salt", "x" * 16),
                             ("verifier", b"short")]:
            database = Mock()
            database.execute.return_value.fetchone.return_value = {**base, field: value}
            with self.subTest(field=field, value=value), patch.object(pm, "password_kdf") as kdf:
                with self.assertRaises(ValueError):
                    pm.login_account(database, "alice", "master password")
                kdf.assert_not_called()

    def test_symlinked_directories_are_rejected_without_permission_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir(mode=0o755)
            before = target.stat().st_mode
            link = Path(directory) / "linked"
            link.symlink_to(target, target_is_directory=True)
            for opener in [pm.open_database, pm.configure_logging]:
                with self.subTest(opener=opener.__name__), self.assertRaises(OSError):
                    opener(link / "file")
            self.assertEqual(target.stat().st_mode, before)
            self.assertEqual(list(target.iterdir()), [])

    def test_fifo_and_directory_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            folder = Path(directory) / "folder"
            folder.mkdir()
            for target in [fifo, folder]:
                for opener in [pm.open_database, pm.configure_logging]:
                    with self.subTest(target=target.name, opener=opener.__name__), self.assertRaises(OSError):
                        opener(target)


if __name__ == "__main__":
    unittest.main()
