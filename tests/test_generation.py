"""The generator has one fixed option; manual passwords remain hidden."""

import contextlib
import io
import string
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm
import security


class PasswordGenerationTests(unittest.TestCase):
    def test_generated_password_has_twenty_allowed_characters(self):
        password = security.generate_password()
        self.assertEqual(len(password), 20)
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+?"
        self.assertLessEqual(set(password), set(alphabet))

    def test_symbols_are_available_to_the_random_choice(self):
        # A fixed choice checks symbol support without relying on random luck.
        with patch.object(security.secrets, "choice", return_value="!") as choice:
            self.assertEqual(security.generate_password(), "!" * 20)
        self.assertIn("!", choice.call_args.args[0])

    def test_generation_needs_only_one_choice(self):
        session = Mock()
        session.read_input.return_value = "y"
        password = pm.prompt_entry_password(session)
        self.assertEqual(len(password), 20)
        session.read_input.assert_called_once()

    def test_manual_password_is_read_with_hidden_input(self):
        session = Mock()
        session.read_input.side_effect = ["", "manual secret"]
        self.assertEqual(pm.prompt_entry_password(session), "manual secret")
        self.assertTrue(session.read_input.call_args.kwargs["hidden"])

    def test_invalid_choice_and_password_are_retried(self):
        session = Mock()
        session.read_input.side_effect = ["maybe", "n", "", "x" * 1025, "manual secret"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(pm.prompt_entry_password(session), "manual secret")
        self.assertEqual(session.read_input.call_count, 5)
        self.assertTrue(all(call.kwargs["hidden"] for call in session.read_input.call_args_list[2:]))
        self.assertNotIn("manual secret", output.getvalue())
        self.assertNotIn("x" * 1025, output.getvalue())


if __name__ == "__main__":
    unittest.main()
