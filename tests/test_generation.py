"""Password generation rules and hidden/manual prompt behavior."""

import string
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm


class PasswordGenerationTests(unittest.TestCase):
    def test_length_alphabet_and_required_groups(self):
        symbols = "!@#$%^&*()-_=+?"
        for length in [12, 20, 128]:
            for include_symbols in [False, True]:
                with self.subTest(length=length, symbols=include_symbols):
                    password = pm.generate_password(length, include_symbols=include_symbols)
                    self.assertEqual(len(password), length)
                    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
                    if include_symbols:
                        groups.append(symbols)
                    self.assertLessEqual(set(password), set("".join(groups)))
                    for group in groups:
                        self.assertTrue(any(character in group for character in password))

    def test_uses_secure_choice_and_rejects_missing_groups(self):
        accepted = "aA1!bbbbbbbb"
        with patch.object(pm.secrets, "choice", side_effect="a" * 12 + accepted) as choice:
            self.assertEqual(pm.generate_password(12), accepted)
        self.assertEqual(choice.call_count, 24)

    def test_invalid_lengths_and_option_types(self):
        for value in [0, 11, 129, 10**10, True, None, "20", 20.0]:
            with self.subTest(length=value), self.assertRaises(ValueError):
                pm.generate_password(value)
        for value in [None, "yes", 1]:
            with self.subTest(symbols=value), self.assertRaises(ValueError):
                pm.generate_password(include_symbols=value)

    def test_manual_input_remains_hidden(self):
        for answer in ["", "n", "N"]:
            session = Mock()
            session.read_input.side_effect = [answer, "manual secret"]
            with self.subTest(answer=answer), patch.object(pm, "generate_password") as generator:
                self.assertEqual(pm.prompt_entry_password(session), "manual secret")
                session.read_input.assert_called_with("Entry password: ", hidden=True)
                generator.assert_not_called()

    def test_invalid_prompt_choices_never_generate(self):
        options = [["maybe"], ["y", "-1"], ["y", "1.5"], ["y", "9" * 5000],
                   ["y", "１２"], ["y", "20", "maybe"]]
        for answers in options:
            session = Mock()
            session.read_input.side_effect = answers
            with self.subTest(answers=answers[:2]), patch.object(pm, "generate_password") as generator:
                with self.assertRaises(ValueError):
                    pm.prompt_entry_password(session)
                generator.assert_not_called()

    def test_timeout_during_generation_options_never_generates(self):
        for position in range(3):
            session = Mock()
            answers = ["y", "20", "n"]
            answers[position] = pm.SessionExpired(pm.INACTIVITY_MESSAGE)
            session.read_input.side_effect = answers
            with self.subTest(position=position), patch.object(pm, "generate_password") as generator:
                with self.assertRaises(pm.SessionExpired):
                    pm.prompt_entry_password(session)
                generator.assert_not_called()

    def test_expired_session_cannot_generate_after_options(self):
        session = Mock()
        session.read_input.side_effect = ["y", "20", "n"]
        session.require_unlocked.side_effect = pm.SessionExpired(pm.INACTIVITY_MESSAGE)
        with patch.object(pm, "generate_password") as generator:
            with self.assertRaises(pm.SessionExpired):
                pm.prompt_entry_password(session)
            generator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
