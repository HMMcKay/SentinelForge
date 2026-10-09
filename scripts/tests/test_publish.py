"""Credential-check regressions using synthetic files and a mocked Git index."""

import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location(
    "check_publish", Path(__file__).resolve().parents[1] / "check-publish.py",
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class PublishCheckTests(unittest.TestCase):
    def check(self, content: dict[str, bytes], environment: str = "") -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if environment:
                (root / ".env").write_text(environment, encoding="utf-8")

            def fake_git(*arguments: str) -> bytes:
                if arguments == ("rev-parse", "--show-toplevel"):
                    return str(root).encode()
                if arguments == ("ls-files", "-z"):
                    return "\0".join(content).encode() + b"\0"
                if arguments[0] == "show":
                    return content[arguments[1][1:]]
                raise AssertionError(f"Unexpected Git call: {arguments}")

            with patch.object(CHECK, "git_bytes", side_effect=fake_git):
                return CHECK.check_index()

    def test_secret_detection_does_not_return_key_or_value(self) -> None:
        credential = "synthetic-credential-for-this-test-only"
        failures = self.check(
            {"README.md": credential.encode()}, f"ADMIN_SECRET={credential}\n",
        )
        self.assertEqual(failures, ["Local credential found in: README.md"])
        self.assertNotIn(credential, str(failures))
        self.assertNotIn("ADMIN_SECRET", str(failures))

    def test_private_generated_paths_are_rejected(self) -> None:
        paths = ["private/OWNER_GUIDE.md", ".env", "output/result.txt", "agent/obj/a.cs"]
        failures = self.check(dict.fromkeys(paths, b"synthetic fixture"))
        self.assertEqual(len(failures), len(paths))

    def test_clean_source_and_example_configuration_pass(self) -> None:
        self.assertEqual(self.check({"README.md": b"public", ".env.example": b"example"}), [])

    def test_common_token_shape_is_rejected_without_returning_token(self) -> None:
        token = b"ghp_" + b"A" * 40
        failures = self.check({"source.py": token})
        self.assertEqual(failures, ["Possible token or private key in: source.py"])
        self.assertNotIn(token.decode(), str(failures))

    def test_presentation_xml_is_checked(self) -> None:
        credential = "synthetic-deck-credential-for-this-test"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as deck:
            deck.writestr("ppt/slides/slide1.xml", credential)
        failures = self.check(
            {"docs/demo.pptx": buffer.getvalue()}, f"API_TOKEN={credential}\n",
        )
        self.assertEqual(failures, ["Local credential found in: docs/demo.pptx"])


if __name__ == "__main__":
    unittest.main()
